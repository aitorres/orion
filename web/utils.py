import hashlib
import io
import logging
import sqlite3
from datetime import datetime
from typing import Any, Final

import qrcode
import qrcode.image.svg
import requests
from django.conf import settings
from django.contrib import messages
from django.core.cache import cache
from django.http import HttpRequest

REQUESTS_TIMEOUT_IN_SECONDS: Final[int] = 10
BATCH_SIZE: Final[int] = 20
LIST_REPOS_PAGE_SIZE: Final[int] = 1000
LIST_REPOS_MAX_PAGES: Final[int] = 1000

# Short TTL for the health check; longer for everything else.
HEALTH_CACHE_TTL_SECONDS: Final[int] = 30

_CSV_INJECTION_PREFIXES: Final[tuple[str, ...]] = ("=", "+", "-", "@", "\t", "\r")


def sanitize_csv_cell(value: Any) -> str:
    """Return `value` coerced to `str`, neutralized against CSV injection.

    Any cell beginning with a spreadsheet formula trigger character is prefixed
    with a single quote so spreadsheet apps render it as literal text rather
    than evaluating it as a formula.
    """

    text = "" if value is None else str(value)

    if text.startswith(_CSV_INJECTION_PREFIXES):
        return "'" + text

    return text


def _stable_key(values: list[str]) -> str:
    """Return a process-stable digest of `values` for use in cache keys."""

    joined = "\x00".join(sorted(values)).encode("utf-8")
    return hashlib.sha1(joined, usedforsecurity=False).hexdigest()


def _cache_ttl() -> int:
    """Return the configured TTL for upstream lookups, with a sane default."""

    return int(getattr(settings, "ORION_UPSTREAM_CACHE_TTL", 300))


def get_pds_status(use_cache: bool = True) -> bool:
    """Check the status of the PDS service (cached for a short period)."""

    cache_key = "orion:pds:status"
    if use_cache:
        cached = cache.get(cache_key)
        if cached is not None:
            return cached

    try:
        response = requests.get(
            f"{settings.PDS_HOSTNAME}/xrpc/_health", timeout=REQUESTS_TIMEOUT_IN_SECONDS
        )
        ok = response.status_code == 200
    except requests.RequestException as e:
        logging.exception("Failed to connect to PDS service for health check.", exc_info=e)
        ok = False

    cache.set(cache_key, ok, HEALTH_CACHE_TTL_SECONDS)
    return ok


def get_pds_accounts(use_cache: bool = True) -> list[dict[str, Any]]:
    """Retrieve a list of PDS repos (DIDs and status only)."""

    cache_key = "orion:pds:accounts"
    if use_cache:
        cached = cache.get(cache_key)
        if cached is not None:
            return cached

    repos: list[dict[str, Any]] = []
    cursor: str | None = None
    try:
        for _ in range(LIST_REPOS_MAX_PAGES):
            params: dict[str, Any] = {"limit": LIST_REPOS_PAGE_SIZE}

            if cursor:
                params["cursor"] = cursor

            response = requests.get(
                f"{settings.PDS_HOSTNAME}/xrpc/com.atproto.sync.listRepos",
                params=params,
                timeout=REQUESTS_TIMEOUT_IN_SECONDS,
            )
            response.raise_for_status()
            data = response.json()
            repos.extend(data.get("repos", []))
            cursor = data.get("cursor")
            if not cursor:
                break
        else:
            logging.warning(
                "listRepos pagination hit the max page limit of %d; results may be truncated.",
                LIST_REPOS_MAX_PAGES,
            )
        accounts = [{**repo, "order": idx + 1} for idx, repo in enumerate(repos)]
    except requests.RequestException as e:
        logging.exception("Failed to retrieve PDS accounts.", exc_info=e)
        return []

    cache.set(cache_key, accounts, _cache_ttl())
    return accounts


def get_appview_visible_dids(dids: list[str], use_cache: bool = True) -> set[str] | None:
    """Return DIDs that are visible on AppView; `None` if lookup fails."""

    if not dids:
        return set()

    cache_key = f"orion:appview:visible:{_stable_key(dids)}"
    if use_cache:
        cached = cache.get(cache_key)
        if cached is not None:
            return cached

    try:
        response = requests.get(
            f"{settings.APPVIEW_HOSTNAME}/xrpc/app.bsky.actor.getProfiles",
            params=[("actors", did) for did in dids],
            timeout=REQUESTS_TIMEOUT_IN_SECONDS,
        )
        response.raise_for_status()
        data = response.json()
        profiles = data.get("profiles", [])
        visible = {
            did
            for profile in profiles
            if isinstance(profile, dict)
            for did in [profile.get("did")]
            if isinstance(did, str)
        }
    except requests.RequestException as e:
        logging.exception("Failed to retrieve appview profile batch.", exc_info=e)
        return None

    cache.set(cache_key, visible, _cache_ttl())
    return visible


def _with_appview_status(infos: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Attach `appview_suspended` to infos when appview lookup is available."""

    if not infos:
        return infos

    dids = [did for info in infos for did in [info.get("did")] if isinstance(did, str)]
    visible_dids = get_appview_visible_dids(dids)

    for info in infos:
        did = info.get("did")
        if not did or visible_dids is None:
            info["appview_suspended"] = None
        else:
            info["appview_suspended"] = did not in visible_dids

    return infos


def get_pds_account_batch_infos(
    dids: list[str], use_cache: bool = True
) -> list[dict[str, Any]]:
    """Retrieve account infos for a single batch of DIDs."""

    if len(dids) > BATCH_SIZE:
        logging.error(
            "Requested %d DIDs, which exceeds the batch size limit of %d.",
            len(dids),
            BATCH_SIZE,
        )
        raise ValueError(f"At most {BATCH_SIZE} DIDs per request.")

    if not dids:
        return []

    cache_key = f"orion:pds:batch_infos:{_stable_key(dids)}"
    if use_cache:
        cached = cache.get(cache_key)
        if cached is not None:
            return cached

    try:
        response = requests.get(
            f"{settings.PDS_HOSTNAME}/xrpc/com.atproto.admin.getAccountInfos",
            auth=("admin", settings.PDS_ADMIN_PASSWORD),
            params=[("dids", did) for did in dids],
            timeout=REQUESTS_TIMEOUT_IN_SECONDS,
        )
        response.raise_for_status()
        data = response.json()
        infos = data.get("infos", [])
        infos = _with_appview_status(infos)
    except requests.RequestException as e:
        logging.exception("Failed to retrieve account infos from PDS.", exc_info=e)
        return []

    cache.set(cache_key, infos, _cache_ttl())
    return infos


def get_pds_account_info(did: str) -> dict[str, Any] | None:
    """Retrieve detailed information about a specific PDS account by DID."""

    try:
        response = requests.get(
            f"{settings.PDS_HOSTNAME}/xrpc/com.atproto.admin.getAccountInfo",
            auth=("admin", settings.PDS_ADMIN_PASSWORD),
            params={"did": did},
            timeout=REQUESTS_TIMEOUT_IN_SECONDS,
        )
        response.raise_for_status()
        data = response.json()
        visible_dids = get_appview_visible_dids([did])
        data["appview_suspended"] = None if visible_dids is None else did not in visible_dids
        return data
    except requests.RequestException as e:
        logging.exception("Failed to retrieve account info for DID %s.", did, exc_info=e)
        return None


def get_gatekeeper_required_dids(use_cache: bool = True) -> set[str]:
    """Query the gatekeeper database to get DIDs that have 2FA required/enabled."""

    if not settings.GATEKEEPER_ENABLED or not settings.GATEKEEPER_DB_PATH:
        return set()

    cache_key = "orion:gatekeeper:required_dids"
    if use_cache:
        cached = cache.get(cache_key)
        if cached is not None:
            return cached

    try:
        conn = sqlite3.connect(settings.GATEKEEPER_DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT did FROM two_factor_accounts WHERE required = 1")
        rows = cursor.fetchall()
        conn.close()
        result = {row[0] for row in rows}
    except sqlite3.Error as e:
        logging.exception("Failed to query gatekeeper database.", exc_info=e)
        return set()

    cache.set(cache_key, result, _cache_ttl())
    return result


def _format_pds_status(account: dict[str, Any]) -> str:
    """Render an account's PDS status from the listRepos payload."""

    if account.get("active"):
        return "Active"
    status = account.get("status")
    if isinstance(status, str):
        return status.title()
    return "Unknown"


_APPVIEW_STATUS_LABELS: Final[dict[Any, str]] = {
    True: "Suspended",
    False: "Active",
}


def _format_appview_status(info: dict[str, Any]) -> str:
    """Render an account's AppView status from a PDS info payload."""

    return _APPVIEW_STATUS_LABELS.get(info.get("appview_suspended"), "Unknown")


def _build_info_by_did(dids: list[str], use_cache: bool) -> dict[str, dict[str, Any]]:
    """Fetch and index PDS account infos for the given DIDs."""

    info_by_did: dict[str, dict[str, Any]] = {}
    for i in range(0, len(dids), BATCH_SIZE):
        batch = dids[i : i + BATCH_SIZE]
        for info in get_pds_account_batch_infos(batch, use_cache=use_cache):
            did = info.get("did")
            if isinstance(did, str):
                info_by_did[did] = info
    return info_by_did


def get_enriched_accounts(use_cache: bool = True) -> list[dict[str, Any]]:
    """Return the fully-resolved account rows used by the dashboard table.

    Each row contains everything the frontend needs to render the table:
    order, did, handle, pds_status, appview_status and (optionally) 2FA status.
    The result is cached as a single blob so repeated dashboard loads served
    by the data API stay cheap.
    """

    cache_key = "orion:dashboard:enriched_accounts"
    if use_cache:
        cached = cache.get(cache_key)
        if cached is not None:
            return cached

    accounts = get_pds_accounts(use_cache=use_cache)
    if not accounts:
        cache.set(cache_key, [], _cache_ttl())
        return []

    dids = [acc["did"] for acc in accounts if acc.get("did")]
    info_by_did = _build_info_by_did(dids, use_cache=use_cache)

    gatekeeper_dids: set[str] = (
        get_gatekeeper_required_dids(use_cache=use_cache)
        if settings.GATEKEEPER_ENABLED
        else set()
    )

    rows: list[dict[str, Any]] = []
    for account in accounts:
        did = account.get("did", "")
        info = info_by_did.get(did, {})

        pds_status = _format_pds_status(account)
        appview_status = _format_appview_status(info)
        if pds_status == "Deactivated" and appview_status == "Suspended":
            appview_status = "Suspended or Deactivated"

        row: dict[str, Any] = {
            "order": account.get("order"),
            "did": did,
            "handle": info.get("handle") or "unknown",
            "pds_status": pds_status,
            "appview_status": appview_status,
        }
        if settings.GATEKEEPER_ENABLED:
            row["twofa_status"] = "Enabled" if did in gatekeeper_dids else "Disabled"
        rows.append(row)

    cache.set(cache_key, rows, _cache_ttl())
    return rows


def invalidate_dashboard_cache() -> None:
    """Drop the cached dashboard data so the next load re-fetches from upstream."""

    cache.delete("orion:dashboard:enriched_accounts")
    cache.delete("orion:pds:accounts")
    cache.delete("orion:gatekeeper:required_dids")


def delete_pds_account(_request: HttpRequest, did: str) -> bool:
    """Delete a PDS account by DID."""

    try:
        response = requests.post(
            f"{settings.PDS_HOSTNAME}/xrpc/com.atproto.admin.deleteAccount",
            auth=("admin", settings.PDS_ADMIN_PASSWORD),
            json={"did": did},
            timeout=REQUESTS_TIMEOUT_IN_SECONDS,
        )
        response.raise_for_status()
        logging.info("Successfully deleted PDS account with DID %s.", did)
        invalidate_dashboard_cache()
        return True
    except requests.RequestException as e:
        logging.exception("Failed to delete PDS account with DID %s.", did, exc_info=e)
        return False


def takedown_pds_account(_request: HttpRequest, did: str) -> bool:
    """Takedown a PDS account by DID."""

    try:
        takedown_ref = str(int(datetime.now().timestamp()))

        payload = {
            "subject": {"$type": "com.atproto.admin.defs#repoRef", "did": did},
            "takedown": {"applied": True, "ref": takedown_ref},
        }

        response = requests.post(
            f"{settings.PDS_HOSTNAME}/xrpc/com.atproto.admin.updateSubjectStatus",
            auth=("admin", settings.PDS_ADMIN_PASSWORD),
            json=payload,
            timeout=REQUESTS_TIMEOUT_IN_SECONDS,
        )
        response.raise_for_status()
        logging.info("Successfully takedown PDS account with DID %s.", did)
        invalidate_dashboard_cache()
        return True
    except requests.RequestException as e:
        logging.exception("Failed to takedown PDS account with DID %s.", did, exc_info=e)
        return False


def untakedown_pds_account(_request: HttpRequest, did: str) -> bool:
    """Untakedown a PDS account by DID."""

    try:
        payload = {
            "subject": {"$type": "com.atproto.admin.defs#repoRef", "did": did},
            "takedown": {"applied": False},
        }

        response = requests.post(
            f"{settings.PDS_HOSTNAME}/xrpc/com.atproto.admin.updateSubjectStatus",
            auth=("admin", settings.PDS_ADMIN_PASSWORD),
            json=payload,
            timeout=REQUESTS_TIMEOUT_IN_SECONDS,
        )
        response.raise_for_status()
        logging.info("Successfully untakedown PDS account with DID %s.", did)
        invalidate_dashboard_cache()
        return True
    except requests.RequestException as e:
        logging.exception("Failed to untakedown PDS account with DID %s.", did, exc_info=e)
        return False


def update_pds_account_password(request: HttpRequest, did: str) -> bool:
    """Reset a PDS account's password using ``new_password`` from the request."""

    new_password = request.POST.get("new_password", "")
    confirm_password = request.POST.get("confirm_password", "")

    if not new_password:
        messages.error(request, "New password is required.")
        return False

    if new_password != confirm_password:
        messages.error(request, "New passwords do not match.")
        return False

    try:
        response = requests.post(
            f"{settings.PDS_HOSTNAME}/xrpc/com.atproto.admin.updateAccountPassword",
            auth=("admin", settings.PDS_ADMIN_PASSWORD),
            json={"did": did, "password": new_password},
            timeout=REQUESTS_TIMEOUT_IN_SECONDS,
        )
        response.raise_for_status()
        logging.info("Successfully reset password for PDS account with DID %s.", did)
        return True
    except requests.RequestException as e:
        logging.exception(
            "Failed to reset password for PDS account with DID %s.", did, exc_info=e
        )
        messages.error(request, "Failed to reset password on the PDS.")
        return False


def generate_totp_qr_svg(config_url: str) -> str:
    """Return an inline SVG `<svg>` element encoding the given otpauth:// URL."""

    qr = qrcode.QRCode(
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=2,
        image_factory=qrcode.image.svg.SvgPathImage,
    )
    qr.add_data(config_url)
    qr.make(fit=True)

    img = qr.make_image()
    buffer = io.BytesIO()
    img.save(buffer)

    svg = buffer.getvalue().decode("utf-8")

    # Strip the XML declaration so the SVG can be embedded inline in HTML.
    if svg.startswith("<?xml"):
        svg = svg.split("?>", 1)[1].lstrip()

    return svg
