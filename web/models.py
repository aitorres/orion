import uuid

from django.conf import settings
from django.db import models
from django.db.models import Q


class AuditLogEvent(models.TextChoices):
    LOGIN = "LOGIN", "Login"
    LOGIN_FAILED = "LOGIN_FAILED", "Login Failed"
    LOGOUT = "LOGOUT", "Logout"
    DELETE = "DELETE", "Delete"
    TAKEDOWN = "TAKEDOWN", "Takedown"
    UNTAKEDOWN = "UNTAKEDOWN", "Untakedown"
    PASSWORD_CHANGE = "PASSWORD_CHANGE", "Password Change"
    PASSWORD_CHANGE_FAILED = "PASSWORD_CHANGE_FAILED", "Password Change Failed"
    PASSWORD_RESET = "PASSWORD_RESET", "Password Reset"
    PASSWORD_RESET_FAILED = "PASSWORD_RESET_FAILED", "Password Reset Failed"
    TWO_FACTOR_ENABLED = "TWO_FACTOR_ENABLED", "Two-Factor Enabled"
    TWO_FACTOR_VERIFIED = "TWO_FACTOR_VERIFIED", "Two-Factor Verified"
    TWO_FACTOR_FAILED = "TWO_FACTOR_FAILED", "Two-Factor Failed"
    INFO = "INFO", "Info"


class AuditLog(models.Model):
    """Audit log for tracking user events."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="audit_logs",
        null=True,
        blank=True,
    )
    event = models.CharField(max_length=30, choices=AuditLogEvent.choices)
    description = models.TextField(blank=True, null=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=512, blank=True, null=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Audit Log"
        verbose_name_plural = "Audit Logs"
        constraints = [
            models.CheckConstraint(
                condition=Q(event__in=AuditLogEvent.values),
                name="valid_event_type",
            )
        ]

    def __str__(self):
        return f"{self.user} - {self.event} - {self.created_at}"
