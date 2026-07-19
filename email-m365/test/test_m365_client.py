from unittest import TestCase
from unittest.mock import MagicMock, patch

from email_m365_injector.client.m365_client import M365Client


def _response(status_code=202, payload=None, text=""):
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    if payload is None:
        resp.json.side_effect = ValueError("no json")
    else:
        resp.json.return_value = payload
    return resp


def _client():
    return M365Client(
        tenant_id="tenant-1",
        client_id="client-1",
        client_secret="secret-1",
        graph_base_url="https://graph.microsoft.com/v1.0",
    )


class SendMailTest(TestCase):
    @patch("email_m365_injector.client.m365_client.requests.post")
    @patch("email_m365_injector.client.m365_client.msal.ConfidentialClientApplication")
    def test_success_returns_accepted(self, msal_app, post):
        msal_app.return_value.acquire_token_for_client.return_value = {
            "access_token": "token-abc"
        }
        post.return_value = _response(status_code=202)

        result = _client().send_mail(
            sender="alerts@contoso.com",
            message={"subject": "hi"},
            save_to_sent_items=True,
        )

        self.assertTrue(result.success)
        # Bearer token attached and the sendMail endpoint targets the sender.
        self.assertEqual(
            post.call_args.kwargs["headers"]["Authorization"], "Bearer token-abc"
        )
        self.assertTrue(
            post.call_args.args[0].endswith("/users/alerts%40contoso.com/sendMail")
        )
        self.assertEqual(
            post.call_args.kwargs["json"]["saveToSentItems"],
            True,
        )

    @patch("email_m365_injector.client.m365_client.requests.post")
    @patch("email_m365_injector.client.m365_client.msal.ConfidentialClientApplication")
    def test_graph_error_is_surfaced(self, msal_app, post):
        msal_app.return_value.acquire_token_for_client.return_value = {
            "access_token": "token-abc"
        }
        post.return_value = _response(
            status_code=403,
            payload={
                "error": {
                    "code": "ErrorAccessDenied",
                    "message": "Access is denied.",
                }
            },
        )

        result = _client().send_mail(sender="a@b.com", message={})
        self.assertFalse(result.success)
        self.assertIn("ErrorAccessDenied", result.message)
        self.assertIn("Access is denied.", result.message)

    @patch("email_m365_injector.client.m365_client.requests.post")
    @patch("email_m365_injector.client.m365_client.msal.ConfidentialClientApplication")
    def test_token_failure_is_surfaced(self, msal_app, post):
        msal_app.return_value.acquire_token_for_client.return_value = {
            "error": "invalid_client",
            "error_description": "bad secret",
        }

        result = _client().send_mail(sender="a@b.com", message={})
        self.assertFalse(result.success)
        self.assertIn("bad secret", result.message)
        post.assert_not_called()

    @patch("email_m365_injector.client.m365_client.requests.post")
    @patch("email_m365_injector.client.m365_client.msal.ConfidentialClientApplication")
    def test_timeout_is_handled(self, msal_app, post):
        from requests.exceptions import Timeout

        msal_app.return_value.acquire_token_for_client.return_value = {
            "access_token": "token-abc"
        }
        post.side_effect = Timeout()

        result = _client().send_mail(sender="a@b.com", message={})
        self.assertFalse(result.success)
        self.assertIn("timed out", result.message)
