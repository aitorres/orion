from django.urls import path

from web.views import (
    OrionLoginView,
    account_action_view,
    account_infos_api_view,
    audit_log_view,
    change_password_view,
    dashboard_view,
    export_accounts_csv_view,
    healthcheck_view,
    logout_view,
)

urlpatterns = [
    path("health/", healthcheck_view, name="healthcheck"),
    path("dashboard/", dashboard_view, name="dashboard"),
    path("api/account-infos/", account_infos_api_view, name="account_infos_api"),
    path("accounts/<str:did>/<str:action>/", account_action_view, name="account_action"),
    path("audit-log/", audit_log_view, name="audit_log"),
    path("change-password/", change_password_view, name="change_password"),
    path("export-accounts-csv/", export_accounts_csv_view, name="export_accounts_csv"),
    path("logout/", logout_view, name="logout"),
    path("", OrionLoginView.as_view(), name="login"),
]
