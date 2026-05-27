from django.apps import AppConfig


class WebConfig(AppConfig):
    name = "web"

    def ready(self) -> None:
        # pylint: disable=import-outside-toplevel,unused-import
        from web import signals  # noqa: F401
