import logging
import sqlite3
from datetime import datetime
from typing import Any, Final

import requests
from django.conf import settings

REQUESTS_TIMEOUT_IN_SECONDS: Final[int] = 10
BATCH_SIZE: Final[int] = 20


def get_pds_status() -> bool:
    """Check the status of the PDS service."""

    try:
        response = requests.get(
            f"{settings.PDS_HOSTNAME}/xrpc/_health", timeout=REQUESTS_TIMEOUT_IN_SECONDS
        )
        return response.status_code == 200
    except requests.RequestException as e:
        logging.exception("Failed to connect to PDS service for health check.", exc_info=e)
        return False


def get_pds_accounts() -> list[dict[str, Any]]:
    """Retrieve a list of PDS repos (DIDs and status only)."""

    try:
        response = requests.get(
            f"{settings.PDS_HOSTNAME}/xrpc/com.atproto.sync.listRepos",
            timeout=REQUESTS_TIMEOUT_IN_SECONDS,
        )
        response.raise_for_status()
        data = response.json()
        return [{**repo, "order": idx + 1} for idx, repo in enumerate(data["repos"])]
    except requests.RequestException as e:
        logging.exception("Failed to retrieve PDS accounts.", exc_info=e)
        return []


def get_appview_visible_dids(dids: list[str]) -> set[str] | None:
    """Return DIDs that are visible on AppView; ``None`` if lookup fails."""

    if not dids:
        return set()

    try:
        response = requests.get(
            f"{settings.APPVIEW_HOSTNAME}/xrpc/app.bsky.actor.getProfiles",
            params=[("actors", did) for did in dids],
            timeout=REQUESTS_TIMEOUT_IN_SECONDS,
        )
        response.raise_for_status()
        data = response.json()
        profiles = data.get("profiles", [])
        return {
            did
            for profile in profiles
            if isinstance(profile, dict)
            for did in [profile.get("did")]
            if isinstance(did, str)
        }
    except requests.RequestException as e:
        logging.exception("Failed to retrieve appview profile batch.", exc_info=e)
        return None


def _with_appview_status(infos: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Attach ``appview_suspended`` to infos when appview lookup is available."""

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


def get_pds_account_batch_infos(dids: list[str]) -> list[dict[str, Any]]:
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
        return _with_appview_status(infos)
    except requests.RequestException as e:
        logging.exception("Failed to retrieve account infos from PDS.", exc_info=e)
        return []


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


def get_gatekeeper_required_dids() -> set[str]:
    """Query the gatekeeper database to get DIDs that have 2FA required/enabled."""

    if not settings.GATEKEEPER_ENABLED or not settings.GATEKEEPER_DB_PATH:
        return set()

    try:
        conn = sqlite3.connect(settings.GATEKEEPER_DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT did FROM two_factor_accounts WHERE required = 1")
        rows = cursor.fetchall()
        conn.close()
        return {row[0] for row in rows}
    except sqlite3.Error as e:
        logging.exception("Failed to query gatekeeper database.", exc_info=e)
        return set()


def delete_pds_account(did: str) -> bool:
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
        return True
    except requests.RequestException as e:
        logging.exception("Failed to delete PDS account with DID %s.", did, exc_info=e)
        return False


def takedown_pds_account(did: str) -> bool:
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
        return True
    except requests.RequestException as e:
        logging.exception("Failed to takedown PDS account with DID %s.", did, exc_info=e)
        return False


def untakedown_pds_account(did: str) -> bool:
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
        return True
    except requests.RequestException as e:
        logging.exception("Failed to untakedown PDS account with DID %s.", did, exc_info=e)
        return False
