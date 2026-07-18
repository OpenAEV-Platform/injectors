from unittest import TestCase
from unittest.mock import MagicMock, patch

from teams.client.graph_auth import GraphAuthError
from teams.client.teams_client import TeamsClient


def _client(token="tok"):
    token_provider = MagicMock()
    token_provider.get_access_token.return_value = token
    return TeamsClient(token_provider=token_provider, timeout=10), token_provider


def _response(status_code, payload=None, text=""):
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    if payload is None:
        resp.json.side_effect = ValueError("no json")
    else:
        resp.json.return_value = payload
    return resp


class PostChannelMessageTest(TestCase):
    @patch("teams.client.teams_client.requests.post")
    def test_success_returns_message_id_and_weburl(self, post):
        post.return_value = _response(
            201, payload={"id": "1700000000", "webUrl": "https://teams/msg"}
        )
        client, _ = _client()
        result = client.post_channel_message("team", "channel", {"body": {}})
        self.assertTrue(result.success)
        self.assertEqual(result.message_id, "1700000000")
        self.assertEqual(result.web_url, "https://teams/msg")
        # Bearer token must be attached.
        self.assertEqual(
            post.call_args.kwargs["headers"]["Authorization"], "Bearer tok"
        )
        self.assertIn("/teams/team/channels/channel/messages", post.call_args.args[0])

    @patch("teams.client.teams_client.requests.post")
    def test_graph_error_is_surfaced(self, post):
        post.return_value = _response(
            403, payload={"error": {"message": "Missing role permissions"}}
        )
        client, _ = _client()
        result = client.post_channel_message("team", "channel", {"body": {}})
        self.assertFalse(result.success)
        self.assertEqual(result.status_code, 403)
        self.assertIn("Missing role permissions", result.message)

    @patch("teams.client.teams_client.requests.post")
    def test_timeout_is_handled(self, post):
        from requests.exceptions import Timeout

        post.side_effect = Timeout()
        client, _ = _client()
        result = client.post_channel_message("team", "channel", {"body": {}})
        self.assertFalse(result.success)
        self.assertIn("timed out", result.message)

    def test_auth_failure_short_circuits(self):
        client, token_provider = _client()
        token_provider.get_access_token.side_effect = GraphAuthError("bad token")
        result = client.post_channel_message("team", "channel", {"body": {}})
        self.assertFalse(result.success)
        self.assertIn("bad token", result.message)


class PostChatMessageTest(TestCase):
    @patch("teams.client.teams_client.requests.post")
    def test_targets_chat_endpoint(self, post):
        post.return_value = _response(201, payload={"id": "1"})
        client, _ = _client()
        result = client.post_chat_message("19:chat@thread.v2", {"body": {}})
        self.assertTrue(result.success)
        self.assertIn("/chats/19:chat@thread.v2/messages", post.call_args.args[0])
