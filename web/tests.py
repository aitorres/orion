# pylint: disable=too-many-public-methods

from unittest.mock import Mock, patch

import requests
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase, override_settings
from django_otp import DEVICE_ID_SESSION_KEY
from django_otp.oath import totp
from django_otp.plugins.otp_totp.models import TOTPDevice

from web.models import AuditLog, AuditLogEvent
from web.utils import (
    delete_pds_account,
    get_pds_account_batch_infos,
    get_pds_account_info,
    get_pds_accounts,
    get_pds_status,
    takedown_pds_account,
    untakedown_pds_account,
)


class BaseViewTest(TestCase):
    """Base test case with shared setUp for view tests."""

    def setUp(self):
        """Set up test environment."""

        cache.clear()
        User = get_user_model()
        User.objects.create_user(username="testuser", password="testpass")

    def _mark_otp_verified(self, user):
        """Attach a confirmed TOTP device to ``user`` and mark the session verified."""

        device, _ = TOTPDevice.objects.get_or_create(
            user=user, name="default", defaults={"confirmed": True}
        )

        if not device.confirmed:
            device.confirmed = True
            device.save()

        session = self.client.session
        session[DEVICE_ID_SESSION_KEY] = device.persistent_id
        session.save()
        return device

    def authenticate(self):
        """Log in the test user and mark the session as OTP-verified."""
        user = self.get_user()
        self.client.force_login(user, backend="django.contrib.auth.backends.ModelBackend")
        self._mark_otp_verified(user)

    def authenticate_password_only(self):
        """Log in without satisfying the OTP step (for 2FA enforcement tests)."""
        self.client.force_login(
            self.get_user(), backend="django.contrib.auth.backends.ModelBackend"
        )

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


class ChangePasswordViewTests(BaseViewTest):
    """Tests for the change password view."""

    def test_change_password_requires_login(self):
        """Test that the change password page requires authentication."""
        response = self.client.get("/change-password/")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/?next=/change-password/", response.url)

    def test_change_password_get_renders_form(self):
        """Test that GET renders the change password form."""
        self.authenticate()
        response = self.client.get("/change-password/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Change Password")
        self.assertContains(response, "Current Password")
        self.assertContains(response, "New Password")
        self.assertContains(response, "Confirm New Password")

    def test_change_password_success(self):
        """Test successful password change."""
        self.authenticate()
        response = self.client.post(
            "/change-password/",
            {
                "current_password": "testpass",
                "new_password": "newpassword123",
                "confirm_password": "newpassword123",
            },
        )
        self.assertRedirects(response, "/dashboard/", fetch_redirect_response=False)

        self.client.logout()
        login_response = self.client.post(
            "/", {"username": "testuser", "password": "newpassword123"}
        )
        self.assertEqual(login_response.status_code, 302)

    def test_change_password_wrong_current_password(self):
        """Test that wrong current password shows error."""
        self.authenticate()
        response = self.client.post(
            "/change-password/",
            {
                "current_password": "wrongpassword",
                "new_password": "newpassword123",
                "confirm_password": "newpassword123",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Current password is incorrect")

    def test_change_password_new_passwords_dont_match(self):
        """Test that mismatched new passwords show error."""
        self.authenticate()
        response = self.client.post(
            "/change-password/",
            {
                "current_password": "testpass",
                "new_password": "newpassword123",
                "confirm_password": "differentpassword",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "New passwords do not match")

    def test_change_password_same_as_current(self):
        """Test that new password same as current shows error."""
        self.authenticate()
        response = self.client.post(
            "/change-password/",
            {
                "current_password": "testpass",
                "new_password": "testpass",
                "confirm_password": "testpass",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "New password must be different from current password")

    def test_change_password_creates_audit_log(self):
        """Test that successful password change creates an audit log entry."""
        self.authenticate()
        self.client.post(
            "/change-password/",
            {
                "current_password": "testpass",
                "new_password": "newpassword123",
                "confirm_password": "newpassword123",
            },
        )

        log = AuditLog.objects.filter(event=AuditLogEvent.PASSWORD_CHANGE).first()
        self.assertIsNotNone(log)
        self.assertEqual(log.description, "User changed their password")
        self.assertEqual(log.user.username, "testuser")


@override_settings(
    PDS_HOSTNAME="https://localhost",
    PDS_ADMIN_PASSWORD="admin",
    APPVIEW_HOSTNAME="https://api.bsky.localhost",
)
class AccountInfosApiViewTests(BaseViewTest):
    """Tests for the account infos API view."""

    def test_account_infos_requires_login(self):
        """Test that the account infos API requires authentication."""
        response = self.client.get("/api/account-infos/", {"dids": ["did:plc:123"]})
        self.assertEqual(response.status_code, 302)
        self.assertIn("/?next=/api/account-infos/", response.url)

    def test_account_infos_rejects_non_get(self):
        """Test that non-GET methods are rejected."""
        self.authenticate()
        response = self.client.post("/api/account-infos/", {"dids": ["did:plc:123"]})
        self.assertEqual(response.status_code, 405)

    def test_account_infos_no_dids_returns_empty(self):
        """Test that missing dids param returns an empty infos list."""
        self.authenticate()
        response = self.client.get("/api/account-infos/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"infos": []})

    def test_account_infos_exceeds_batch_size(self):
        """Test that passing more than BATCH_SIZE DIDs returns 400."""
        self.authenticate()
        dids = [f"did:plc:{i}" for i in range(21)]
        response = self.client.get("/api/account-infos/", {"dids": dids})
        self.assertEqual(response.status_code, 400)

    @patch("web.views.get_pds_account_batch_infos")
    def test_account_infos_success(self, mock_batch: Mock):
        """Test successful fetch returns infos as JSON."""
        self.authenticate()
        mock_batch.return_value = [
            {"did": "did:plc:123", "handle": "alice.bsky.social"},
            {"did": "did:plc:456", "handle": "bob.bsky.social"},
        ]

        response = self.client.get(
            "/api/account-infos/",
            {"dids": ["did:plc:123", "did:plc:456"]},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {
                "infos": [
                    {"did": "did:plc:123", "handle": "alice.bsky.social"},
                    {"did": "did:plc:456", "handle": "bob.bsky.social"},
                ]
            },
        )
        mock_batch.assert_called_once_with(["did:plc:123", "did:plc:456"])


@override_settings(
    PDS_HOSTNAME="https://localhost",
    PDS_ADMIN_PASSWORD="admin",
    APPVIEW_HOSTNAME="https://api.bsky.localhost",
)
class UtilsTests(TestCase):
    """Tests for the utils module."""

    def setUp(self):
        cache.clear()

    @patch("web.utils.requests.get")
    def test_get_pds_status_success(self, mock_get: Mock):
        """Test get_pds_status returns True when PDS is healthy."""
        mock_get.return_value = Mock(status_code=200)

        result = get_pds_status()

        self.assertTrue(result)
        mock_get.assert_called_once_with(
            "https://localhost/xrpc/_health",
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

    @patch("web.utils.requests.get")
    def test_get_pds_accounts_success(self, mock_get: Mock):
        """Test get_pds_accounts returns list of repos from listRepos."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "repos": [{"did": "did:plc:123"}, {"did": "did:plc:456"}]
        }
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        result = get_pds_accounts()

        self.assertEqual(
            result, [{"did": "did:plc:123", "order": 1}, {"did": "did:plc:456", "order": 2}]
        )

    @patch("web.utils.requests.get")
    def test_get_pds_accounts_request_exception(self, mock_get: Mock):
        """Test get_pds_accounts returns empty list on failure."""
        mock_get.side_effect = requests.RequestException("Connection refused")

        result = get_pds_accounts()

        self.assertEqual(result, [])

    @patch("web.utils.requests.get")
    def test_get_pds_accounts_paginates_with_cursor(self, mock_get: Mock):
        """Test get_pds_accounts follows the cursor across multiple pages."""
        page1 = Mock()
        page1.json.return_value = {
            "repos": [{"did": "did:plc:1"}, {"did": "did:plc:2"}],
            "cursor": "next-cursor",
        }
        page1.raise_for_status = Mock()

        page2 = Mock()
        page2.json.return_value = {
            "repos": [{"did": "did:plc:3"}],
            "cursor": None,
        }
        page2.raise_for_status = Mock()

        mock_get.side_effect = [page1, page2]

        result = get_pds_accounts()

        self.assertEqual(
            result,
            [
                {"did": "did:plc:1", "order": 1},
                {"did": "did:plc:2", "order": 2},
                {"did": "did:plc:3", "order": 3},
            ],
        )
        self.assertEqual(mock_get.call_count, 2)
        first_params = mock_get.call_args_list[0].kwargs["params"]
        second_params = mock_get.call_args_list[1].kwargs["params"]
        self.assertNotIn("cursor", first_params)
        self.assertEqual(second_params["cursor"], "next-cursor")
        self.assertEqual(first_params["limit"], 1000)
        self.assertEqual(second_params["limit"], 1000)

    @patch("web.utils.requests.get")
    def test_get_pds_accounts_pagination_failure_returns_empty(self, mock_get: Mock):
        """Test get_pds_accounts returns empty list if a later page fails."""
        page1 = Mock()
        page1.json.return_value = {
            "repos": [{"did": "did:plc:1"}],
            "cursor": "next-cursor",
        }
        page1.raise_for_status = Mock()

        mock_get.side_effect = [page1, requests.RequestException("boom")]

        result = get_pds_accounts()

        self.assertEqual(result, [])

    def test_get_pds_account_batch_infos_empty(self):
        """Test get_pds_account_batch_infos returns empty list for empty input."""
        result = get_pds_account_batch_infos([])

        self.assertEqual(result, [])

    @patch("web.utils.requests.get")
    def test_get_pds_account_batch_infos_success(self, mock_get: Mock):
        """Test get_pds_account_batch_infos returns infos for a batch of DIDs."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "infos": [
                {
                    "did": "did:plc:123",
                    "handle": "alice.bsky.social",
                    "email": "alice@example.com",
                },
                {
                    "did": "did:plc:456",
                    "handle": "bob.bsky.social",
                    "email": "bob@example.com",
                },
            ]
        }
        mock_response.raise_for_status = Mock()

        mock_appview_response = Mock()
        mock_appview_response.json.return_value = {
            "profiles": [
                {"did": "did:plc:123"},
            ]
        }
        mock_appview_response.raise_for_status = Mock()
        mock_get.side_effect = [mock_response, mock_appview_response]

        result = get_pds_account_batch_infos(["did:plc:123", "did:plc:456"])

        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["handle"], "alice.bsky.social")
        self.assertEqual(result[1]["handle"], "bob.bsky.social")
        self.assertEqual(result[0]["appview_suspended"], False)
        self.assertEqual(result[1]["appview_suspended"], True)
        self.assertEqual(mock_get.call_count, 2)
        mock_get.assert_any_call(
            "https://localhost/xrpc/com.atproto.admin.getAccountInfos",
            auth=("admin", "admin"),
            params=[("dids", "did:plc:123"), ("dids", "did:plc:456")],
            timeout=10,
        )
        mock_get.assert_any_call(
            "https://api.bsky.localhost/xrpc/app.bsky.actor.getProfiles",
            params=[("actors", "did:plc:123"), ("actors", "did:plc:456")],
            timeout=10,
        )

    @patch("web.utils.requests.get")
    def test_get_pds_account_batch_infos_missing_infos_key(self, mock_get: Mock):
        """Test get_pds_account_batch_infos returns empty list if infos key missing."""
        mock_response = Mock()
        mock_response.json.return_value = {}
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        result = get_pds_account_batch_infos(["did:plc:123"])

        self.assertEqual(result, [])

    @patch("web.utils.requests.get")
    def test_get_pds_account_batch_infos_request_exception(self, mock_get: Mock):
        """Test get_pds_account_batch_infos returns empty list on request failure."""
        mock_get.side_effect = requests.RequestException("Connection refused")

        result = get_pds_account_batch_infos(["did:plc:123"])

        self.assertEqual(result, [])

    def test_get_pds_account_batch_infos_exceeds_batch_size(self):
        """Test get_pds_account_batch_infos raises ValueError when over batch size."""
        dids = [f"did:plc:{i}" for i in range(21)]

        with self.assertRaises(ValueError):
            get_pds_account_batch_infos(dids)

    @patch("web.utils.requests.get")
    def test_get_pds_account_info_success(self, mock_get: Mock):
        """Test get_pds_account_info returns account info on success."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "did": "did:plc:123",
            "handle": "alice.bsky.social",
            "email": "alice@example.com",
        }
        mock_response.raise_for_status = Mock()

        mock_appview_response = Mock()
        mock_appview_response.json.return_value = {"profiles": [{"did": "did:plc:123"}]}
        mock_appview_response.raise_for_status = Mock()
        mock_get.side_effect = [mock_response, mock_appview_response]

        result = get_pds_account_info("did:plc:123")

        self.assertEqual(
            result,
            {
                "did": "did:plc:123",
                "handle": "alice.bsky.social",
                "email": "alice@example.com",
                "appview_suspended": False,
            },
        )
        self.assertEqual(mock_get.call_count, 2)
        mock_get.assert_any_call(
            "https://localhost/xrpc/com.atproto.admin.getAccountInfo",
            auth=("admin", "admin"),
            params={"did": "did:plc:123"},
            timeout=10,
        )
        mock_get.assert_any_call(
            "https://api.bsky.localhost/xrpc/app.bsky.actor.getProfiles",
            params=[("actors", "did:plc:123")],
            timeout=10,
        )

    @patch("web.utils.requests.get")
    def test_get_pds_account_info_request_exception(self, mock_get: Mock):
        """Test get_pds_account_info returns None on request failure."""
        mock_get.side_effect = requests.RequestException("Connection refused")

        result = get_pds_account_info("did:plc:123")

        self.assertIsNone(result)

    @patch("web.utils.requests.post")
    def test_delete_pds_account_success(self, mock_post: Mock):
        """Test delete_pds_account returns True on success."""
        mock_response = Mock()
        mock_response.raise_for_status = Mock()
        mock_post.return_value = mock_response

        result = delete_pds_account("did:plc:123")

        self.assertTrue(result)
        mock_post.assert_called_once_with(
            "https://localhost/xrpc/com.atproto.admin.deleteAccount",
            auth=("admin", "admin"),
            json={"did": "did:plc:123"},
            timeout=10,
        )

    @patch("web.utils.requests.post")
    def test_delete_pds_account_request_exception(self, mock_post: Mock):
        """Test delete_pds_account returns False on request failure."""
        mock_post.side_effect = requests.RequestException("Connection refused")

        result = delete_pds_account("did:plc:123")

        self.assertFalse(result)

    @patch("web.utils.requests.post")
    def test_takedown_pds_account_success(self, mock_post: Mock):
        """Test takedown_pds_account returns True on success."""
        mock_response = Mock()
        mock_response.raise_for_status = Mock()
        mock_post.return_value = mock_response

        result = takedown_pds_account("did:plc:123")

        self.assertTrue(result)
        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args[1]
        self.assertEqual(
            call_kwargs["url"] if "url" in call_kwargs else mock_post.call_args[0][0],
            "https://localhost/xrpc/com.atproto.admin.updateSubjectStatus",
        )
        payload = call_kwargs["json"]
        self.assertEqual(payload["subject"]["$type"], "com.atproto.admin.defs#repoRef")
        self.assertEqual(payload["subject"]["did"], "did:plc:123")
        self.assertTrue(payload["takedown"]["applied"])
        self.assertIn("ref", payload["takedown"])

    @patch("web.utils.requests.post")
    def test_takedown_pds_account_request_exception(self, mock_post: Mock):
        """Test takedown_pds_account returns False on request failure."""
        mock_post.side_effect = requests.RequestException("Connection refused")

        result = takedown_pds_account("did:plc:123")

        self.assertFalse(result)

    @patch("web.utils.requests.post")
    def test_untakedown_pds_account_success(self, mock_post: Mock):
        """Test untakedown_pds_account returns True on success."""
        mock_response = Mock()
        mock_response.raise_for_status = Mock()
        mock_post.return_value = mock_response

        result = untakedown_pds_account("did:plc:123")

        self.assertTrue(result)
        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args[1]
        payload = call_kwargs["json"]
        self.assertEqual(payload["subject"]["$type"], "com.atproto.admin.defs#repoRef")
        self.assertEqual(payload["subject"]["did"], "did:plc:123")
        self.assertFalse(payload["takedown"]["applied"])
        self.assertNotIn("ref", payload["takedown"])

    @patch("web.utils.requests.post")
    def test_untakedown_pds_account_request_exception(self, mock_post: Mock):
        """Test untakedown_pds_account returns False on request failure."""
        mock_post.side_effect = requests.RequestException("Connection refused")

        result = untakedown_pds_account("did:plc:123")

        self.assertFalse(result)


class TwoFactorSetupTests(BaseViewTest):
    """Tests for the mandatory TOTP setup view."""

    def test_setup_requires_login(self):
        """Anonymous users hitting the setup URL are redirected to login."""
        response = self.client.get("/2fa/setup/")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/?next=/2fa/setup/", response.url)

    def test_setup_get_renders_qr_and_creates_unconfirmed_device(self):
        """GET shows the QR SVG and creates a single unconfirmed TOTP device."""
        self.authenticate_password_only()
        response = self.client.get("/2fa/setup/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "<svg")
        self.assertContains(response, "Set up two-factor")
        user = self.get_user()
        self.assertTrue(TOTPDevice.objects.filter(user=user, confirmed=False).exists())

    def test_setup_get_is_idempotent(self):
        """Repeated GETs reuse the same unconfirmed device."""
        self.authenticate_password_only()
        self.client.get("/2fa/setup/")
        self.client.get("/2fa/setup/")
        user = self.get_user()
        self.assertEqual(TOTPDevice.objects.filter(user=user).count(), 1)

    def test_setup_post_invalid_token_does_not_confirm(self):
        """POST with a wrong token re-renders the form and leaves the device unconfirmed."""
        self.authenticate_password_only()
        self.client.get("/2fa/setup/")
        response = self.client.post("/2fa/setup/", {"token": "000000"})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Invalid verification code")
        user = self.get_user()
        self.assertFalse(TOTPDevice.objects.filter(user=user, confirmed=True).exists())

    def test_setup_post_valid_token_confirms_device_and_logs_event(self):
        """POST with the correct token confirms the device and writes an audit log."""
        self.authenticate_password_only()
        self.client.get("/2fa/setup/")
        user = self.get_user()
        device = TOTPDevice.objects.get(user=user, confirmed=False)
        token = totp(device.bin_key, step=device.step, t0=device.t0, digits=device.digits)
        response = self.client.post("/2fa/setup/", {"token": f"{token:0{device.digits}d}"})
        self.assertRedirects(response, "/dashboard/", fetch_redirect_response=False)
        device.refresh_from_db()
        self.assertTrue(device.confirmed)
        self.assertTrue(
            AuditLog.objects.filter(user=user, event=AuditLogEvent.TWO_FACTOR_ENABLED).exists()
        )

    def test_setup_redirects_to_verify_when_already_enrolled(self):
        """Users with a confirmed device are bounced to the verify view."""
        self.authenticate_password_only()
        user = self.get_user()
        TOTPDevice.objects.create(user=user, name="default", confirmed=True)
        response = self.client.get("/2fa/setup/")
        self.assertRedirects(response, "/2fa/verify/", fetch_redirect_response=False)


class TwoFactorVerifyTests(BaseViewTest):
    """Tests for the TOTP verification view."""

    def _create_confirmed_device(self):
        """Create and return a confirmed TOTP device for the test user."""
        user = self.get_user()
        return TOTPDevice.objects.create(user=user, name="default", confirmed=True)

    def test_verify_requires_login(self):
        """Anonymous users hitting the verify URL are redirected to login."""
        response = self.client.get("/2fa/verify/")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/?next=/2fa/verify/", response.url)

    def test_verify_get_renders_form(self):
        """GET renders the verification form when the user has a confirmed device."""
        self._create_confirmed_device()
        self.authenticate_password_only()
        response = self.client.get("/2fa/verify/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Two-factor verification")

    def test_verify_redirects_to_setup_when_no_device(self):
        """Without a confirmed device, the verify view bounces to setup."""
        self.authenticate_password_only()
        response = self.client.get("/2fa/verify/")
        self.assertRedirects(response, "/2fa/setup/", fetch_redirect_response=False)

    def test_verify_post_valid_token_redirects_to_dashboard(self):
        """A valid TOTP unlocks the dashboard and writes a verified audit log."""
        device = self._create_confirmed_device()
        self.authenticate_password_only()
        token = totp(device.bin_key, step=device.step, t0=device.t0, digits=device.digits)
        response = self.client.post("/2fa/verify/", {"token": f"{token:0{device.digits}d}"})
        self.assertRedirects(response, "/dashboard/", fetch_redirect_response=False)
        user = self.get_user()
        self.assertTrue(
            AuditLog.objects.filter(
                user=user, event=AuditLogEvent.TWO_FACTOR_VERIFIED
            ).exists()
        )

    def test_verify_post_invalid_token_logs_failure(self):
        """An invalid TOTP re-renders with an error and writes a failure audit log."""
        self._create_confirmed_device()
        self.authenticate_password_only()
        response = self.client.post("/2fa/verify/", {"token": "000000"})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Invalid verification code")
        user = self.get_user()
        self.assertTrue(
            AuditLog.objects.filter(user=user, event=AuditLogEvent.TWO_FACTOR_FAILED).exists()
        )


class TwoFactorEnforcementTests(BaseViewTest):
    """Tests for the Enforce2FAMiddleware."""

    def test_unverified_user_without_device_is_redirected_to_setup(self):
        """Unverified users without a device are redirected to setup on protected pages."""
        self.authenticate_password_only()
        for path in ("/dashboard/", "/audit-log/", "/change-password/"):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertRedirects(response, "/2fa/setup/", fetch_redirect_response=False)

    def test_unverified_user_with_device_is_redirected_to_verify(self):
        """Unverified users with a device are redirected to verify on protected pages."""
        user = self.get_user()
        TOTPDevice.objects.create(user=user, name="default", confirmed=True)
        self.authenticate_password_only()
        for path in ("/dashboard/", "/audit-log/", "/change-password/"):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertRedirects(response, "/2fa/verify/", fetch_redirect_response=False)

    def test_logout_is_reachable_without_2fa(self):
        """Logging out is exempt from 2FA enforcement."""
        self.authenticate_password_only()
        response = self.client.get("/logout/")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "/")

    def test_healthcheck_is_reachable_without_auth(self):
        """The healthcheck endpoint is always reachable without auth."""
        response = self.client.get("/health/")
        self.assertEqual(response.status_code, 200)

    def test_verified_user_can_reach_dashboard(self):
        """An OTP-verified user can reach the dashboard normally."""
        self.authenticate()
        response = self.client.get("/dashboard/")
        self.assertEqual(response.status_code, 200)
