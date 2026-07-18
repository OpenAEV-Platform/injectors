import time
from unittest import TestCase
from unittest.mock import MagicMock, patch

from teams.client.graph_auth import GraphAuthError, GraphTokenProvider


def _provider():
    return GraphTokenProvider(
        tenant_id="tenant",
        client_id="client",
        client_secret="secret",
        refresh_token="refresh-1",
        timeout=10,
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


class GraphTokenProviderTest(TestCase):
    def test_token_url(self):
        self.assertEqual(
            _provider().token_url,
            "https://login.microsoftonline.com/tenant/oauth2/v2.0/token",
        )

    @patch("teams.client.graph_auth.requests.post")
    def test_returns_access_token_and_rotates_refresh_token(self, post):
        post.return_value = _response(
            payload={
                "access_token": "abc",
                "expires_in": 3600,
                "refresh_token": "refresh-2",
            }
        )
        provider = _provider()
        self.assertEqual(provider.get_access_token(), "abc")
        # A second call within the validity window must not hit the network again.
        self.assertEqual(provider.get_access_token(), "abc")
        self.assertEqual(post.call_count, 1)
        # The rotated refresh token is used on the next refresh.
        self.assertEqual(post.call_args.kwargs["data"]["refresh_token"], "refresh-1")

    @patch("teams.client.graph_auth.requests.post")
    def test_refreshes_when_token_expired(self, post):
        post.return_value = _response(
            payload={"access_token": "abc", "expires_in": 3600}
        )
        provider = _provider()
        provider.get_access_token()
        provider._expires_at = time.time() - 1  # force expiry
        provider.get_access_token()
        self.assertEqual(post.call_count, 2)

    @patch("teams.client.graph_auth.requests.post")
    def test_raises_on_error_payload(self, post):
        post.return_value = _response(
            status_code=400,
            payload={
                "error": "invalid_grant",
                "error_description": "token expired",
            },
        )
        with self.assertRaises(GraphAuthError) as ctx:
            _provider().get_access_token()
        self.assertIn("invalid_grant", str(ctx.exception))

    @patch("teams.client.graph_auth.requests.post")
    def test_raises_on_network_error(self, post):
        import requests

        post.side_effect = requests.RequestException("boom")
        with self.assertRaises(GraphAuthError):
            _provider().get_access_token()
