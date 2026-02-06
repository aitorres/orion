from django.urls import path

from web.views import (
    OrionLoginView,
    account_action_view,
    audit_log_view,
    change_password_view,
    dashboard_view,
    healthcheck_view,
    logout_view,
)

urlpatterns = [
    path("health/", healthcheck_view, name="healthcheck"),
    path("dashboard/", dashboard_view, name="dashboard"),
    path("accounts/<str:did>/<str:action>/", account_action_view, name="account_action"),
    path("audit-log/", audit_log_view, name="audit_log"),
    path("change-password/", change_password_view, name="change_password"),
    path("logout/", logout_view, name="logout"),
    path("", OrionLoginView.as_view(), name="login"),
]
