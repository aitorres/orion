from django.contrib.auth.views import LoginView
from django.http import HttpRequest, HttpResponse


class OrionLoginView(LoginView):
    """Render the login page, main entry point for a non-authenticated user."""

    template_name = "login.html"
    next_page = "/dashboard/"


def healthcheck_view(request: HttpRequest) -> HttpResponse:
    """A simple view to check if the application is running."""
    return HttpResponse("OK")
