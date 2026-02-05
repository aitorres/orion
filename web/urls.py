from django.urls import path

from web.views import OrionLoginView, dashboard_view, healthcheck_view, logout_view

urlpatterns = [
    path("health/", healthcheck_view, name="healthcheck"),
    path("dashboard/", dashboard_view, name="dashboard"),
    path("logout/", logout_view, name="logout"),
    path("", OrionLoginView.as_view(), name="login"),
]
