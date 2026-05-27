"""Helpers for writing :class:`web.models.AuditLog` entries.

The helper centralizes extraction of client metadata (IP, user-agent) from
`HttpRequest` objects so every audit entry — whether written from a view or
from a signal — captures the same fields consistently.
"""

from typing import Any, Optional

from django.http import HttpRequest

from web.models import AuditLog, AuditLogEvent

_USER_AGENT_MAX_LENGTH = 512


def _client_ip(request: Optional[HttpRequest]) -> Optional[str]:
    """Return the best-effort client IP for `request`, honoring X-Forwarded-For."""

    if request is None:
        return None

    forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
    if forwarded:
        # First entry is the original client; the rest are proxy hops.
        return forwarded.split(",")[0].strip() or None

    return request.META.get("REMOTE_ADDR") or None


def _user_agent(request: Optional[HttpRequest]) -> Optional[str]:
    """Return the request's User-Agent, truncated to the model field length."""

    if request is None:
        return None

    ua = request.META.get("HTTP_USER_AGENT")
    if not ua:
        return None

    return ua[:_USER_AGENT_MAX_LENGTH]


def record_audit(
    request: Optional[HttpRequest],
    *,
    user: Optional[Any],
    event: AuditLogEvent,
    description: str,
) -> AuditLog:
    """Create an AuditLog row, capturing IP/UA from `request` if any."""

    return AuditLog.objects.create(
        user=user,
        event=event,
        description=description,
        ip_address=_client_ip(request),
        user_agent=_user_agent(request),
    )
