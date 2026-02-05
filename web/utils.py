import logging
from typing import Any, Final

import requests
from django.conf import settings

REQUESTS_TIMEOUT_IN_SECONDS: Final[int] = 10
BATCH_SIZE: Final[int] = 100


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
    """Retrieve a list of PDS accounts."""

    try:
        response = requests.get(
            f"{settings.PDS_HOSTNAME}/xrpc/com.atproto.sync.listRepos",
            timeout=REQUESTS_TIMEOUT_IN_SECONDS,
        )
        response.raise_for_status()
        data = response.json()
        repos = data["repos"]
        return extend_with_account_info(repos)
    except requests.RequestException as e:
        logging.exception("Failed to retrieve PDS accounts.", exc_info=e)
        return []


def extend_with_account_info(repos: list[dict[str, str]]) -> list[dict[str, Any]]:
    """Extend the list of repos with additional account information."""

    if not repos:
        return repos

    dids = [repo["did"] for repo in repos]

    account_infos: dict[str, dict[str, Any]] = {}
    for i in range(0, len(dids), BATCH_SIZE):
        batch = dids[i : i + BATCH_SIZE]
        try:
            response = requests.get(
                f"{settings.PDS_HOSTNAME}/xrpc/com.atproto.admin.getAccountInfos",
                auth=("admin", settings.PDS_ADMIN_PASSWORD),
                params=[("dids", did) for did in batch],
                timeout=REQUESTS_TIMEOUT_IN_SECONDS,
            )
            response.raise_for_status()
            data = response.json()
            for info in data.get("infos", []):
                account_infos[info["did"]] = info
        except requests.RequestException as e:
            logging.exception("Failed to retrieve account infos from PDS.", exc_info=e)

    expanded_repos = []
    for repo in repos:
        did = repo["did"]
        account_info = account_infos.get(did, {})
        expanded_repo = {
            **repo,
            "handle": account_info.get("handle", "unknown"),
            "email": account_info.get("email", "unknown"),
            "indexedAt": account_info.get("createdAt", "unknown"),
        }
        expanded_repos.append(expanded_repo)

    return expanded_repos
