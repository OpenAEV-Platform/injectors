import json
from unittest import TestCase

from slack_injector.contracts_slack import (
    CONTENT_BLOCKS,
    CONTENT_TEXT,
    KEY_BLOCKS_JSON,
    KEY_CONTENT_TYPE,
    KEY_MESSAGE,
    KEY_TITLE,
)
from slack_injector.helpers.slack_helper import SlackPayloadBuilder


class BuildTextPayloadTest(TestCase):
    def test_text_payload_has_channel_and_fallback_only(self):
        payload = SlackPayloadBuilder.build(
            "C123",
            {
                KEY_CONTENT_TYPE: CONTENT_TEXT,
                KEY_TITLE: "Incident",
                KEY_MESSAGE: "Something happened",
            },
        )
        self.assertEqual(payload["channel"], "C123")
        self.assertEqual(payload["text"], "Incident\nSomething happened")
        self.assertNotIn("blocks", payload)


class BuildBlocksPayloadTest(TestCase):
    def test_default_blocks_built_from_title_and_message(self):
        payload = SlackPayloadBuilder.build(
            "C123",
            {
                KEY_CONTENT_TYPE: CONTENT_BLOCKS,
                KEY_TITLE: "Title",
                KEY_MESSAGE: "Body",
            },
        )
        self.assertIn("blocks", payload)
        # A text fallback is always present for notifications.
        self.assertTrue(payload["text"])
        block_types = [b["type"] for b in payload["blocks"]]
        self.assertEqual(block_types, ["header", "section"])
        self.assertEqual(payload["blocks"][0]["text"]["text"], "Title")
        self.assertEqual(payload["blocks"][1]["text"]["text"], "Body")

    def test_blocks_default_when_content_type_missing(self):
        payload = SlackPayloadBuilder.build("C1", {KEY_TITLE: "T", KEY_MESSAGE: "M"})
        self.assertIn("blocks", payload)

    def test_header_is_truncated_to_slack_limit(self):
        payload = SlackPayloadBuilder.build(
            "C1",
            {
                KEY_CONTENT_TYPE: CONTENT_BLOCKS,
                KEY_TITLE: "x" * 200,
                KEY_MESSAGE: "m",
            },
        )
        self.assertEqual(len(payload["blocks"][0]["text"]["text"]), 150)

    def test_custom_blocks_used_verbatim(self):
        custom = [{"type": "divider"}]
        payload = SlackPayloadBuilder.build(
            "C1",
            {
                KEY_CONTENT_TYPE: CONTENT_BLOCKS,
                KEY_TITLE: "ignored",
                KEY_MESSAGE: "ignored",
                KEY_BLOCKS_JSON: json.dumps(custom),
            },
        )
        self.assertEqual(payload["blocks"], custom)

    def test_invalid_blocks_json_raises(self):
        with self.assertRaises(ValueError):
            SlackPayloadBuilder.build(
                "C1",
                {
                    KEY_CONTENT_TYPE: CONTENT_BLOCKS,
                    KEY_TITLE: "t",
                    KEY_MESSAGE: "m",
                    KEY_BLOCKS_JSON: "{not valid",
                },
            )

    def test_non_array_blocks_json_raises(self):
        with self.assertRaises(ValueError):
            SlackPayloadBuilder.build(
                "C1",
                {
                    KEY_CONTENT_TYPE: CONTENT_BLOCKS,
                    KEY_TITLE: "t",
                    KEY_MESSAGE: "m",
                    KEY_BLOCKS_JSON: '{"type": "divider"}',
                },
            )
