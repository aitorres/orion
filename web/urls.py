from django.urls import path

from web.views import OrionLoginView, healthcheck_view

urlpatterns = [
    path("health/", healthcheck_view, name="healthcheck"),
    path("", OrionLoginView.as_view(), name="login"),
]
