"""Auth-related signal receivers that record audit log entries."""

from typing import Any

from django.contrib.auth.signals import user_login_failed
from django.dispatch import receiver

from web.audit import record_audit
from web.models import AuditLogEvent


@receiver(user_login_failed)
def _on_login_failed(
    sender: Any,  # pylint: disable=unused-argument
    credentials: dict,
    request: Any = None,
    **_: Any,
) -> None:
    """Record a LOGIN_FAILED audit entry for every rejected login attempt."""

    username = credentials.get("username") if isinstance(credentials, dict) else None
    record_audit(
        request,
        user=None,
        event=AuditLogEvent.LOGIN_FAILED,
        description=f"Failed login attempt for username={username!r}",
    )
