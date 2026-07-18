import json
from unittest import TestCase

from teams.contracts_teams import (
    CONTENT_CARD,
    CONTENT_TEXT,
    KEY_CARD_JSON,
    KEY_CONTENT_TYPE,
    KEY_MESSAGE,
    KEY_TITLE,
)
from teams.helpers.teams_helper import (
    ADAPTIVE_CARD_CONTENT_TYPE,
    TeamsPayloadBuilder,
)


class BuildTextBodyTest(TestCase):
    def test_text_body_is_html_with_title_and_message(self):
        body = TeamsPayloadBuilder.build(
            {
                KEY_CONTENT_TYPE: CONTENT_TEXT,
                KEY_TITLE: "Incident",
                KEY_MESSAGE: "line1\nline2",
            }
        )
        self.assertEqual(body["body"]["contentType"], "html")
        content = body["body"]["content"]
        self.assertIn("<b>Incident</b>", content)
        self.assertIn("line1<br>line2", content)
        self.assertNotIn("attachments", body)

    def test_text_body_escapes_html(self):
        body = TeamsPayloadBuilder.build(
            {
                KEY_CONTENT_TYPE: CONTENT_TEXT,
                KEY_TITLE: "<script>",
                KEY_MESSAGE: "a & b <tag>",
            }
        )
        content = body["body"]["content"]
        self.assertNotIn("<script>", content)
        self.assertIn("&lt;script&gt;", content)
        self.assertIn("a &amp; b", content)


class BuildCardBodyTest(TestCase):
    def test_default_card_built_from_title_and_message(self):
        body = TeamsPayloadBuilder.build(
            {
                KEY_CONTENT_TYPE: CONTENT_CARD,
                KEY_TITLE: "Title",
                KEY_MESSAGE: "Body text",
            }
        )
        self.assertIn("attachments", body)
        attachment = body["attachments"][0]
        self.assertEqual(attachment["contentType"], ADAPTIVE_CARD_CONTENT_TYPE)
        # The attachment id must be referenced by the HTML body.
        self.assertIn(attachment["id"], body["body"]["content"])
        card = json.loads(attachment["content"])
        self.assertEqual(card["type"], "AdaptiveCard")
        texts = [b.get("text") for b in card["body"]]
        self.assertIn("Title", texts)
        self.assertIn("Body text", texts)

    def test_card_defaults_when_content_type_missing(self):
        body = TeamsPayloadBuilder.build({KEY_TITLE: "T", KEY_MESSAGE: "M"})
        self.assertIn("attachments", body)

    def test_custom_card_json_is_used_verbatim(self):
        custom = {
            "type": "AdaptiveCard",
            "version": "1.5",
            "body": [{"type": "TextBlock", "text": "custom"}],
        }
        body = TeamsPayloadBuilder.build(
            {
                KEY_CONTENT_TYPE: CONTENT_CARD,
                KEY_TITLE: "ignored",
                KEY_MESSAGE: "ignored",
                KEY_CARD_JSON: json.dumps(custom),
            }
        )
        card = json.loads(body["attachments"][0]["content"])
        self.assertEqual(card["version"], "1.5")
        self.assertEqual(card["body"][0]["text"], "custom")

    def test_invalid_custom_card_json_raises(self):
        with self.assertRaises(ValueError):
            TeamsPayloadBuilder.build(
                {
                    KEY_CONTENT_TYPE: CONTENT_CARD,
                    KEY_TITLE: "t",
                    KEY_MESSAGE: "m",
                    KEY_CARD_JSON: "{not valid json",
                }
            )

    def test_non_object_custom_card_json_raises(self):
        with self.assertRaises(ValueError):
            TeamsPayloadBuilder.build(
                {
                    KEY_CONTENT_TYPE: CONTENT_CARD,
                    KEY_TITLE: "t",
                    KEY_MESSAGE: "m",
                    KEY_CARD_JSON: "[1, 2, 3]",
                }
            )
