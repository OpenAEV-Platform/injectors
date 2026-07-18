from unittest import TestCase
from unittest.mock import MagicMock, patch

from slack_injector.client.slack_client import SlackClient


def _response(status_code=200, payload=None):
    resp = MagicMock()
    resp.status_code = status_code
    if payload is None:
        resp.json.side_effect = ValueError("no json")
    else:
        resp.json.return_value = payload
    return resp


class PostMessageTest(TestCase):
    @patch("slack_injector.client.slack_client.requests.post")
    def test_success_returns_channel_and_ts(self, post):
        post.return_value = _response(
            payload={"ok": True, "channel": "C1", "ts": "1.2"}
        )
        client = SlackClient(bot_token="xoxb-test")
        result = client.post_message({"channel": "C1", "text": "hi"})
        self.assertTrue(result.success)
        self.assertEqual(result.channel, "C1")
        self.assertEqual(result.ts, "1.2")
        # Bearer token must be attached and endpoint correct.
        self.assertEqual(
            post.call_args.kwargs["headers"]["Authorization"], "Bearer xoxb-test"
        )
        self.assertTrue(post.call_args.args[0].endswith("/chat.postMessage"))

    @patch("slack_injector.client.slack_client.requests.post")
    def test_ok_false_is_surfaced_as_error(self, post):
        # Slack returns HTTP 200 with ok:false on logical failures.
        post.return_value = _response(
            payload={"ok": False, "error": "channel_not_found"}
        )
        client = SlackClient(bot_token="xoxb-test")
        result = client.post_message({"channel": "bad", "text": "hi"})
        self.assertFalse(result.success)
        self.assertIn("channel_not_found", result.message)

    @patch("slack_injector.client.slack_client.requests.post")
    def test_invalid_blocks_metadata_is_included(self, post):
        post.return_value = _response(
            payload={
                "ok": False,
                "error": "invalid_blocks",
                "response_metadata": {"messages": ["invalid block at 0"]},
            }
        )
        client = SlackClient(bot_token="xoxb-test")
        result = client.post_message({"channel": "C1", "blocks": []})
        self.assertFalse(result.success)
        self.assertIn("invalid_blocks", result.message)
        self.assertIn("invalid block at 0", result.message)

    @patch("slack_injector.client.slack_client.requests.post")
    def test_timeout_is_handled(self, post):
        from requests.exceptions import Timeout

        post.side_effect = Timeout()
        client = SlackClient(bot_token="xoxb-test")
        result = client.post_message({"channel": "C1", "text": "hi"})
        self.assertFalse(result.success)
        self.assertIn("timed out", result.message)

    @patch("slack_injector.client.slack_client.requests.post")
    def test_non_json_response_is_handled(self, post):
        post.return_value = _response(status_code=500, payload=None)
        client = SlackClient(bot_token="xoxb-test")
        result = client.post_message({"channel": "C1", "text": "hi"})
        self.assertFalse(result.success)
        self.assertIn("non-JSON", result.message)
