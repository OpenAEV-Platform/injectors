import json
from unittest import TestCase
from unittest.mock import MagicMock, patch

from email_gws_injector.client.gmail_client import GmailClient

_SA_JSON = json.dumps(
    {
        "type": "service_account",
        "project_id": "p",
        "private_key_id": "k",
        "private_key": "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----\n",
        "client_email": "sa@p.iam.gserviceaccount.com",
        "client_id": "1",
        "token_uri": "https://oauth2.googleapis.com/token",
    }
)


def _response(status_code=200, payload=None, text=""):
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    if payload is None:
        resp.json.side_effect = ValueError("no json")
    else:
        resp.json.return_value = payload
    return resp


def _client(sa_json=_SA_JSON):
    return GmailClient(service_account_json=sa_json)


class SendMessageTest(TestCase):
    @patch("email_gws_injector.client.gmail_client.requests.post")
    @patch(
        "email_gws_injector.client.gmail_client.service_account.Credentials.from_service_account_info"
    )
    def test_success_impersonates_sender_and_returns_id(self, from_info, post):
        creds = MagicMock()
        creds.token = "token-abc"
        from_info.return_value = creds
        post.return_value = _response(
            status_code=200, payload={"id": "msg-1", "threadId": "t-1"}
        )

        result = _client().send_message(sender="alerts@corp.com", raw_message="cmF3")

        self.assertTrue(result.success)
        self.assertIn("msg-1", result.message)
        # The service account must impersonate the sender (domain-wide delegation).
        self.assertEqual(from_info.call_args.kwargs["subject"], "alerts@corp.com")
        self.assertEqual(
            from_info.call_args.kwargs["scopes"],
            ["https://www.googleapis.com/auth/gmail.send"],
        )
        # Bearer token attached and the send endpoint is correct.
        self.assertEqual(
            post.call_args.kwargs["headers"]["Authorization"], "Bearer token-abc"
        )
        self.assertTrue(post.call_args.args[0].endswith("/users/me/messages/send"))
        self.assertEqual(post.call_args.kwargs["json"], {"raw": "cmF3"})

    @patch("email_gws_injector.client.gmail_client.requests.post")
    @patch(
        "email_gws_injector.client.gmail_client.service_account.Credentials.from_service_account_info"
    )
    def test_gmail_error_is_surfaced(self, from_info, post):
        creds = MagicMock()
        creds.token = "token-abc"
        from_info.return_value = creds
        post.return_value = _response(
            status_code=403,
            payload={
                "error": {
                    "code": 403,
                    "status": "PERMISSION_DENIED",
                    "message": "Delegation denied for alerts@corp.com",
                }
            },
        )

        result = _client().send_message(sender="alerts@corp.com", raw_message="cmF3")
        self.assertFalse(result.success)
        self.assertIn("PERMISSION_DENIED", result.message)
        self.assertIn("Delegation denied", result.message)

    def test_invalid_service_account_json_is_surfaced(self):
        result = _client(sa_json="{not-json").send_message(
            sender="a@corp.com", raw_message="cmF3"
        )
        self.assertFalse(result.success)
        self.assertIn("Invalid service account JSON", result.message)

    @patch("email_gws_injector.client.gmail_client.requests.post")
    @patch(
        "email_gws_injector.client.gmail_client.service_account.Credentials.from_service_account_info"
    )
    def test_timeout_is_handled(self, from_info, post):
        from requests.exceptions import Timeout

        creds = MagicMock()
        creds.token = "token-abc"
        from_info.return_value = creds
        post.side_effect = Timeout()

        result = _client().send_message(sender="a@corp.com", raw_message="cmF3")
        self.assertFalse(result.success)
        self.assertIn("timed out", result.message)
