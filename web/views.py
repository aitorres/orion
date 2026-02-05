from django.contrib.auth import logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import LoginView
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect, render

from web.utils import get_pds_accounts, get_pds_status


class OrionLoginView(LoginView):
    """Render the login page, main entry point for a non-authenticated user."""

    template_name = "login.html"
    next_page = "/dashboard/"


def healthcheck_view(request: HttpRequest) -> HttpResponse:
    """A simple view to check if the application is running."""
    return HttpResponse("OK")


def logout_view(request: HttpRequest) -> HttpResponse:
    """Log out the user and redirect to the login page."""
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
