from unittest.mock import Mock, patch

import requests
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings

from web.models import AuditLog, AuditLogEvent
from web.utils import extend_with_account_info, get_pds_accounts, get_pds_status


class BaseViewTest(TestCase):
    """Base test case with shared setUp for view tests."""

    def setUp(self):
        """Set up test environment."""

        User = get_user_model()
        User.objects.create_user(username="testuser", password="testpass")

    def authenticate(self):
        """Log in the test user."""
        self.client.login(username="testuser", password="testpass")

    def get_user(self):
        """Return the test user instance."""
        return get_user_model().objects.get(username="testuser")


class HealthcheckViewTests(BaseViewTest):
    """Tests for the healthcheck view."""

    def test_healthcheck(self):
        """Test that the healthcheck endpoint returns OK."""

        response = self.client.get("/health/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content.decode(), "OK")


class LoginViewTests(BaseViewTest):
    """Tests for the login view."""

    def test_login_page(self):
        """Test that the login page loads correctly."""

        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Sign In")


class DashboardViewTests(BaseViewTest):
    """Tests for the dashboard view."""

    def test_dashboard_requires_login(self):
        """Test that the dashboard page requires authentication."""

        response = self.client.get("/dashboard/")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/?next=/dashboard/", response.url)

    def test_dashboard_page_authenticated(self):
        """Test that the dashboard page loads for authenticated users."""

        self.authenticate()

        response = self.client.get("/dashboard/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Dashboard")

    def test_dashboard_has_audit_log_button(self):
        """Test that the dashboard page has an Audit Log button."""

        self.authenticate()

        response = self.client.get("/dashboard/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Audit Log")
        self.assertContains(response, "/audit-log/")


class AuditLogViewTests(BaseViewTest):
    """Tests for the audit log view."""

    def test_audit_log_requires_login(self):
        """Test that the audit log page requires authentication."""

        response = self.client.get("/audit-log/")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/?next=/audit-log/", response.url)

    def test_audit_log_page_authenticated(self):
        """Test that the audit log page loads for authenticated users."""

        self.authenticate()

        response = self.client.get("/audit-log/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Audit Log")

    def test_audit_log_displays_events(self):
        """Test that audit log events are displayed in the table."""

        self.authenticate()
        user = self.get_user()

        AuditLog.objects.create(
            user=user,
            event=AuditLogEvent.LOGIN,
            description="User logged in successfully",
        )
        AuditLog.objects.create(
            user=user,
            event=AuditLogEvent.LOGOUT,
            description="User logged out",
        )

        response = self.client.get("/audit-log/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Login")
        self.assertContains(response, "Logout")
        self.assertContains(response, "User logged in successfully")
        self.assertContains(response, "User logged out")
        self.assertContains(response, "testuser")

    def test_audit_log_empty(self):
        """Test that audit log shows message when no events exist."""

        self.authenticate()

        response = self.client.get("/audit-log/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "No audit log events found.")

    def test_audit_log_ordered_newest_first(self):
        """Test that audit log events are ordered newest first."""

        self.authenticate()
        user = self.get_user()

        log1 = AuditLog.objects.create(
            user=user,
            event=AuditLogEvent.LOGIN,
            description="First event",
        )
        log2 = AuditLog.objects.create(
            user=user,
            event=AuditLogEvent.LOGOUT,
            description="Second event",
        )

        response = self.client.get("/audit-log/")
        audit_logs = list(response.context["audit_logs"])
        self.assertEqual(audit_logs[0].id, log2.id)
        self.assertEqual(audit_logs[1].id, log1.id)


class AccountActionViewTests(BaseViewTest):
    """Tests for the account action view."""

    def test_action_requires_login(self):
        """Test that the account action page requires authentication."""
        response = self.client.get("/accounts/did:plc:123/takedown/")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/?next=", response.url)

    def test_action_get_shows_confirmation(self):
        """Test that GET renders a confirmation page."""
        self.authenticate()
        response = self.client.get("/accounts/did:plc:123/takedown/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Confirm Takedown")
        self.assertContains(response, "did:plc:123")

    def test_action_get_delete_shows_confirmation(self):
        """Test that GET for delete renders a confirmation page."""
        self.authenticate()
        response = self.client.get("/accounts/did:plc:456/delete/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Confirm Delete")
        self.assertContains(response, "did:plc:456")

    def test_action_invalid_action_returns_400(self):
        """Test that an invalid action returns 400."""
        self.authenticate()
        response = self.client.get("/accounts/did:plc:123/invalid/")
        self.assertEqual(response.status_code, 400)

    def test_action_post_takedown_redirects_to_dashboard(self):
        """Test that POST takedown redirects to dashboard."""
        self.authenticate()
        response = self.client.post("/accounts/did:plc:123/takedown/")
        self.assertRedirects(response, "/dashboard/")

    def test_action_post_delete_redirects_to_dashboard(self):
        """Test that POST delete redirects to dashboard."""
        self.authenticate()
        response = self.client.post("/accounts/did:plc:123/delete/")
        self.assertRedirects(response, "/dashboard/")

    def test_action_post_creates_audit_log_takedown(self):
        """Test that POST takedown creates an audit log entry."""
        self.authenticate()
        self.client.post("/accounts/did:plc:123/takedown/")

        log = AuditLog.objects.filter(event=AuditLogEvent.TAKEDOWN).first()
        self.assertIsNotNone(log)
        self.assertEqual(log.description, "User performed takedown on did:plc:123")
        self.assertEqual(log.user.username, "testuser")

    def test_action_post_creates_audit_log_delete(self):
        """Test that POST delete creates an audit log entry."""
        self.authenticate()
        self.client.post("/accounts/did:plc:789/delete/")

        log = AuditLog.objects.filter(event=AuditLogEvent.DELETE).first()
        self.assertIsNotNone(log)
        self.assertEqual(log.description, "User performed delete on did:plc:789")

    def test_action_post_invalid_action_returns_400(self):
        """Test that POST with an invalid action returns 400."""
        self.authenticate()
        response = self.client.post("/accounts/did:plc:123/invalid/")
        self.assertEqual(response.status_code, 400)

    def test_action_confirmation_has_cancel_button(self):
        """Test that the confirmation page has a cancel button linking to dashboard."""
        self.authenticate()
        response = self.client.get("/accounts/did:plc:123/takedown/")
        self.assertContains(response, "Cancel")
        self.assertContains(response, "/dashboard/")


@override_settings(PDS_HOSTNAME="https://pds.example.com", PDS_ADMIN_PASSWORD="admin123")
class UtilsTests(TestCase):
    """Tests for the utils module."""

    @patch("web.utils.requests.get")
    def test_get_pds_status_success(self, mock_get: Mock):
        """Test get_pds_status returns True when PDS is healthy."""
        mock_get.return_value = Mock(status_code=200)

        result = get_pds_status()

        self.assertTrue(result)
        mock_get.assert_called_once_with(
            "https://pds.example.com/xrpc/_health",
            timeout=10,
        )

    @patch("web.utils.requests.get")
    def test_get_pds_status_failure(self, mock_get: Mock):
        """Test get_pds_status returns False when PDS returns non-200."""
        mock_get.return_value = Mock(status_code=500)

        result = get_pds_status()

        self.assertFalse(result)

    @patch("web.utils.requests.get")
    def test_get_pds_status_request_exception(self, mock_get: Mock):
        """Test get_pds_status returns False when request fails."""
        mock_get.side_effect = requests.RequestException("Connection refused")

        result = get_pds_status()

        self.assertFalse(result)

    @patch("web.utils.extend_with_account_info")
    @patch("web.utils.requests.get")
    def test_get_pds_accounts_success(self, mock_get: Mock, mock_extend: Mock):
        """Test get_pds_accounts returns list of accounts."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "repos": [{"did": "did:plc:123"}, {"did": "did:plc:456"}]
        }
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response
        mock_extend.return_value = [{"did": "did:plc:123", "handle": "user1"}]

        result = get_pds_accounts()

        self.assertEqual(result, [{"did": "did:plc:123", "handle": "user1"}])
        mock_extend.assert_called_once()

    @patch("web.utils.requests.get")
    def test_get_pds_accounts_request_exception(self, mock_get: Mock):
        """Test get_pds_accounts returns empty list on failure."""
        mock_get.side_effect = requests.RequestException("Connection refused")

        result = get_pds_accounts()

        self.assertEqual(result, [])

    def test_extend_with_account_info_empty_repos(self):
        """Test extend_with_account_info returns empty list for empty input."""
        result = extend_with_account_info([])

        self.assertEqual(result, [])

    @patch("web.utils.requests.get")
    def test_extend_with_account_info_success(self, mock_get: Mock):
        """Test extend_with_account_info adds account details to repos."""
        repos = [{"did": "did:plc:123"}, {"did": "did:plc:456"}]
        mock_response = Mock()
        mock_response.json.return_value = {
            "infos": [
                {
                    "did": "did:plc:123",
                    "handle": "alice.bsky.social",
                    "email": "alice@example.com",
                    "createdAt": "2026-01-01T00:00:00Z",
                },
                {
                    "did": "did:plc:456",
                    "handle": "bob.bsky.social",
                    "email": "bob@example.com",
                    "createdAt": "2026-02-01T00:00:00Z",
                },
            ]
        }
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        result = extend_with_account_info(repos)

        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["handle"], "alice.bsky.social")
        self.assertEqual(result[0]["email"], "alice@example.com")
        self.assertEqual(result[1]["handle"], "bob.bsky.social")

    @patch("web.utils.requests.get")
    def test_extend_with_account_info_missing_account(self, mock_get: Mock):
        """Test extend_with_account_info uses defaults for missing accounts."""
        repos = [{"did": "did:plc:123"}]
        mock_response = Mock()
        mock_response.json.return_value = {"infos": []}
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        result = extend_with_account_info(repos)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["handle"], "unknown")
        self.assertEqual(result[0]["email"], "unknown")
        self.assertEqual(result[0]["indexedAt"], "unknown")

    @patch("web.utils.requests.get")
    def test_extend_with_account_info_request_exception(self, mock_get: Mock):
        """Test extend_with_account_info handles request failure gracefully."""
        repos = [{"did": "did:plc:123"}]
        mock_get.side_effect = requests.RequestException("Connection refused")

        result = extend_with_account_info(repos)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["handle"], "unknown")

    @patch("web.utils.requests.get")
    @patch("web.utils.BATCH_SIZE", 2)
    def test_extend_with_account_info_batching(self, mock_get: Mock):
        """Test extend_with_account_info batches large requests."""
        repos = [{"did": f"did:plc:{i}"} for i in range(5)]
        mock_response = Mock()
        mock_response.json.return_value = {"infos": []}
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        extend_with_account_info(repos)

        # With batch size 2 and 5 DIDs, we should have 3 requests
        self.assertEqual(mock_get.call_count, 3)
