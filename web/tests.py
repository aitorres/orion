from django.test import TestCase


class WebTests(TestCase):
    """Tests for the web application."""

    def test_healthcheck(self):
        """Test that the healthcheck endpoint returns OK."""

        response = self.client.get("/health/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content.decode(), "OK")

    def test_login_page(self):
        """Test that the login page loads correctly."""

        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Sign In")
