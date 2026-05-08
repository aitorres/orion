import csv
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
    JsonResponse,
)
from django.shortcuts import redirect, render

from orion import settings
from web.models import AuditLog, AuditLogEvent
from web.utils import (
    BATCH_SIZE,
    delete_pds_account,
    get_enriched_accounts,
    get_gatekeeper_required_dids,
    get_pds_account_batch_infos,
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
    "info": (AuditLogEvent.INFO, lambda _: None),
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

    accounts = get_pds_accounts()

    context = {
        "is_service_healthy": get_pds_status(),
        "account_count": len(accounts),
        "gatekeeper_enabled": settings.GATEKEEPER_ENABLED,
    }

    return render(
        request,
        "dashboard.html",
        context,
    )


@login_required
def accounts_data_api_view(request: HttpRequest) -> HttpResponse:
    """Return all enriched account rows as JSON for the dashboard table."""

    if request.method != "GET":
        return HttpResponseNotAllowed(["GET"])

    use_cache = request.GET.get("refresh") != "1"
    accounts = get_enriched_accounts(use_cache=use_cache)

    return JsonResponse(
        {
            "accounts": accounts,
            "gatekeeper_enabled": settings.GATEKEEPER_ENABLED,
        }
    )


@login_required
def account_infos_api_view(request: HttpRequest) -> HttpResponse:
    """Return account infos for the DIDs provided in the ``dids`` query param.

    Used by the dashboard to progressively populate the accounts table after
    the initial render. At most ``BATCH_SIZE`` DIDs may be requested per call.
    """

    if request.method != "GET":
        return HttpResponseNotAllowed(["GET"])

    dids = request.GET.getlist("dids")
    if not dids:
        return JsonResponse({"infos": []})

    if len(dids) > BATCH_SIZE:
        return HttpResponseBadRequest(f"At most {BATCH_SIZE} DIDs per request.")

    infos = get_pds_account_batch_infos(dids)
    return JsonResponse({"infos": infos})


@login_required
def audit_log_view(request: HttpRequest) -> HttpResponse:
    """Render the audit log page for authenticated users."""

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
                "has_enabled_2fa": did in get_gatekeeper_required_dids(),
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


@login_required
def change_password_view(request: HttpRequest) -> HttpResponse:
    """Handle password change form display (GET) and processing (POST)."""

    if request.method == "GET":
        return render(request, "change_password.html")

    if request.method == "POST":
        current_password = request.POST.get("current_password", "")
        new_password = request.POST.get("new_password", "")
        confirm_password = request.POST.get("confirm_password", "")

        user = request.user

        if not user.check_password(current_password):
            messages.error(request, "Current password is incorrect.")
            return render(request, "change_password.html")

        if new_password != confirm_password:
            messages.error(request, "New passwords do not match.")
            return render(request, "change_password.html")

        if new_password == current_password:
            messages.error(request, "New password must be different from current password.")
            return render(request, "change_password.html")

        user.set_password(new_password)
        user.save()

        assert isinstance(user, get_user_model())
        AuditLog.objects.create(
            user=user,
            event=AuditLogEvent.PASSWORD_CHANGE,
            description="User changed their password",
        )

        messages.success(request, "Password changed successfully.")
        return redirect("dashboard")

    return HttpResponseNotAllowed(["GET", "POST"])


@login_required
def export_accounts_csv_view(request: HttpRequest) -> HttpResponse:
    """Export all accounts to a CSV file."""

    accounts = get_enriched_accounts()
    if not accounts:
        return HttpResponse("No accounts to export.", status=400)

    # Per-DID PDS info (email, etc.) isn't part of the cached enriched rows
    # used to render the dashboard table, so fetch it separately (also cached).
    dids = [account["did"] for account in accounts]
    info_by_did: dict[str, dict] = {}
    for i in range(0, len(dids), BATCH_SIZE):
        batch = dids[i : i + BATCH_SIZE]
        for info in get_pds_account_batch_infos(batch):
            did = info.get("did")
            if isinstance(did, str):
                info_by_did[did] = info

    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = "attachment; filename=accounts_export.csv"

    fieldnames = ["did", "handle", "email", "pds_status", "appview_status"]
    if settings.GATEKEEPER_ENABLED:
        fieldnames.insert(2, "2fa_status")

    writer = csv.DictWriter(response, fieldnames=fieldnames)
    writer.writeheader()

    for account in accounts:
        did = account["did"]
        info = info_by_did.get(did, {})
        row = {
            "did": did,
            "handle": account.get("handle", "unknown"),
            "email": info.get("email", ""),
            "pds_status": account.get("pds_status", "Unknown"),
            "appview_status": account.get("appview_status", "Unknown"),
        }
        if settings.GATEKEEPER_ENABLED:
            row["2fa_status"] = account.get("twofa_status", "Disabled")
        writer.writerow(row)

    assert isinstance(request.user, get_user_model())
    AuditLog.objects.create(
        user=request.user,
        event=AuditLogEvent.INFO,
        description="User exported accounts to CSV",
    )

    return response
