import uuid

from django.conf import settings
from django.db import models
from django.db.models import Q


class AuditLogEvent(models.TextChoices):
    LOGIN = "LOGIN", "Login"
    LOGOUT = "LOGOUT", "Logout"
    DELETE = "DELETE", "Delete"
    TAKEDOWN = "TAKEDOWN", "Takedown"
    UNTAKEDOWN = "UNTAKEDOWN", "Untakedown"
    PASSWORD_CHANGE = "PASSWORD_CHANGE", "Password Change"


class AuditLog(models.Model):
    """Audit log for tracking user events."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="audit_logs",
    )
    event = models.CharField(max_length=20, choices=AuditLogEvent.choices)
    description = models.TextField(blank=True, null=True)

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
