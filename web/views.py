from typing import Callable

from django.contrib import messages
from django.contrib.auth import get_user_model, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import LoginView
from django.http import (
    HttpRequest,
    HttpResponse,
    HttpResponseBadRequest,
    HttpResponseNotAllowed,
)
from django.shortcuts import redirect, render

from web.models import AuditLog, AuditLogEvent
from web.utils import (
    delete_pds_account,
    get_pds_account_info,
    get_pds_accounts,
    get_pds_status,
    takedown_pds_account,
    untakedown_pds_account,
)

ACCOUNT_ACTIONS: dict[str, tuple[AuditLogEvent, Callable]] = {
    "takedown": (AuditLogEvent.TAKEDOWN, takedown_pds_account),
    "untakedown": (AuditLogEvent.UNTAKEDOWN, untakedown_pds_account),
    "delete": (AuditLogEvent.DELETE, delete_pds_account),
}


class OrionLoginView(LoginView):
    """Render the login page, main entry point for a non-authenticated user."""

    template_name = "login.html"
    next_page = "/dashboard/"

    def form_valid(self, form):
        response = super().form_valid(form)
        AuditLog.objects.create(
            user=self.request.user,
            event=AuditLogEvent.LOGIN,
            description="User logged in successfully",
        )
        return response


def healthcheck_view(request: HttpRequest) -> HttpResponse:
    """A simple view to check if the application is running."""
    return HttpResponse("OK")


def logout_view(request: HttpRequest) -> HttpResponse:
    """Log out the user and redirect to the login page."""

    if request.user.is_authenticated:
        AuditLog.objects.create(
            user=request.user,
            event=AuditLogEvent.LOGOUT,
            description="User logged out",
        )

    logout(request)
    return redirect("login")


@login_required
def dashboard_view(request: HttpRequest) -> HttpResponse:
    """Render the dashboard page for authenticated users."""

    if not request.user.is_authenticated:
        return redirect("login")

    return render(
        request,
        "dashboard.html",
        {
            "is_service_healthy": get_pds_status(),
            "accounts": get_pds_accounts(),
        },
    )


@login_required
def audit_log_view(request: HttpRequest) -> HttpResponse:
    """Render the audit log page for authenticated users."""

    if not request.user.is_authenticated:
        return redirect("login")

    audit_logs = AuditLog.objects.select_related("user").order_by("-created_at")

    return render(
        request,
        "audit_log.html",
        {
            "audit_logs": audit_logs,
        },
    )


@login_required
def account_action_view(request: HttpRequest, did: str, action: str) -> HttpResponse:
    """Render a confirmation page (GET) or execute an action (POST) on an account."""

    action = action.lower()

    if action not in ACCOUNT_ACTIONS:
        return HttpResponseBadRequest("Invalid action.")

    if request.method == "GET":
        info = get_pds_account_info(did)
        return render(
            request,
            "account_action.html",
            {
                "did": did,
                "action": action,
                "account_info": info,
            },
        )

    if request.method == "POST":
        assert isinstance(request.user, get_user_model())
        audit_event, handler = ACCOUNT_ACTIONS[action]
        handler(did)

        AuditLog.objects.create(
            user=request.user,
            event=audit_event,
            description=f"User performed {action} on {did}",
        )

        messages.success(request, f"Successfully performed {action} on account {did}.")
        return redirect("dashboard")

    return HttpResponseNotAllowed(["GET", "POST"])
