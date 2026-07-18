"""Build the Microsoft Graph ``chatMessage`` request body from an inject content.

Three rendering modes are supported:

- ``card`` (default): an Adaptive Card. Either auto-built from the title + message,
  or, when a ``card_json`` value is provided, that JSON is sent verbatim.
- ``text``: a plain HTML message body (title bolded, message below).

An Adaptive Card is attached to a Graph message through an ``<attachment>`` tag in
the HTML body that references an entry in the ``attachments`` array, where the card
JSON is passed as a stringified ``content`` (per the Graph API contract).
"""

import html
import json
import uuid
from typing import Dict

from teams.contracts_teams import (
    CONTENT_CARD,
    KEY_CARD_JSON,
    KEY_CONTENT_TYPE,
    KEY_MESSAGE,
    KEY_TITLE,
)

ADAPTIVE_CARD_CONTENT_TYPE = "application/vnd.microsoft.card.adaptive"


class TeamsPayloadBuilder:

    @staticmethod
    def build(content: Dict) -> Dict:
        content_type = (content.get(KEY_CONTENT_TYPE) or CONTENT_CARD).lower()
        title = (content.get(KEY_TITLE) or "").strip()
        message = content.get(KEY_MESSAGE) or ""

        if content_type == CONTENT_CARD:
            card = TeamsPayloadBuilder._resolve_card(content, title, message)
            return TeamsPayloadBuilder._attachment_body(card)
        return TeamsPayloadBuilder._html_body(title, message)

    @staticmethod
    def _resolve_card(content: Dict, title: str, message: str) -> Dict:
        raw = (content.get(KEY_CARD_JSON) or "").strip()
        if raw:
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Custom Adaptive Card JSON is not valid JSON: {exc}"
                ) from exc
            if not isinstance(parsed, dict):
                raise ValueError(
                    "Custom Adaptive Card JSON must be a JSON object (the card content)."
                )
            return parsed
        return TeamsPayloadBuilder._default_card(title, message)

    @staticmethod
    def _default_card(title: str, message: str) -> Dict:
        body = []
        if title:
            body.append(
                {
                    "type": "TextBlock",
                    "size": "Large",
                    "weight": "Bolder",
                    "text": title,
                    "wrap": True,
                }
            )
        body.append({"type": "TextBlock", "text": message, "wrap": True})
        return {
            "type": "AdaptiveCard",
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "version": "1.4",
            "body": body,
        }

    @staticmethod
    def _attachment_body(card: Dict) -> Dict:
        attachment_id = uuid.uuid4().hex
        return {
            "body": {
                "contentType": "html",
                "content": f'<attachment id="{attachment_id}"></attachment>',
            },
            "attachments": [
                {
                    "id": attachment_id,
                    "contentType": ADAPTIVE_CARD_CONTENT_TYPE,
                    "contentUrl": None,
                    "content": json.dumps(card),
                    "name": None,
                    "thumbnailUrl": None,
                }
            ],
        }

    @staticmethod
    def _html_body(title: str, message: str) -> Dict:
        message_html = html.escape(message).replace("\n", "<br>")
        if title:
            content = f"<p><b>{html.escape(title)}</b></p><p>{message_html}</p>"
        else:
            content = f"<p>{message_html}</p>"
        return {"body": {"contentType": "html", "content": content}}
