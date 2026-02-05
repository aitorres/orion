from django.contrib.auth import logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import LoginView
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect, render

from web.models import AuditLog, AuditLogEvent
from web.utils import get_pds_accounts, get_pds_status


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
