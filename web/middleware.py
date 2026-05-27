"""Middleware that enforces mandatory two-factor authentication."""

from typing import Callable

from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect
from django.urls import resolve
from django.urls.exceptions import Resolver404
from django_otp import user_has_device

# URL names that an authenticated-but-not-OTP-verified user is allowed to reach.
_EXEMPT_URL_NAMES = frozenset(
    {
        "login",
        "logout",
        "healthcheck",
        "two_factor_setup",
        "two_factor_verify",
    }
)


class Enforce2FAMiddleware:  # pylint: disable=too-few-public-methods
    """Force every authenticated user through TOTP setup/verify before any other view.

    Must be installed after ``django.contrib.auth.middleware.AuthenticationMiddleware``
    and ``django_otp.middleware.OTPMiddleware`` so that ``request.user`` and
    ``request.user.is_verified()`` are populated.
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        user = getattr(request, "user", None)

        if user is None or not user.is_authenticated or user.is_verified():
            return self.get_response(request)

        try:
            url_name = resolve(request.path_info).url_name
        except Resolver404:
            url_name = None

        if url_name in _EXEMPT_URL_NAMES:
            return self.get_response(request)

        if user_has_device(user, confirmed=True):
            return redirect("two_factor_verify")

        return redirect("two_factor_setup")
