"""Build the Slack ``chat.postMessage`` request body from an inject content.

Two rendering modes are supported:

- ``blocks`` (default): a Block Kit layout. Either auto-built from the title +
  message (a ``header`` block and a ``section`` block), or, when a ``blocks_json``
  value is provided, that JSON array is sent verbatim.
- ``text``: a plain text message (Slack ``mrkdwn``).

A ``text`` fallback is always included: Slack uses it for notifications and
previews even when ``blocks`` are rendered.
"""

import json
from typing import Dict

from slack_injector.contracts_slack import (
    CONTENT_BLOCKS,
    KEY_BLOCKS_JSON,
    KEY_CONTENT_TYPE,
    KEY_MESSAGE,
    KEY_TITLE,
)

# Slack Block Kit hard limits.
_HEADER_MAX = 150
_SECTION_TEXT_MAX = 3000


class SlackPayloadBuilder:

    @staticmethod
    def build(channel: str, content: Dict) -> Dict:
        content_type = (content.get(KEY_CONTENT_TYPE) or CONTENT_BLOCKS).lower()
        title = (content.get(KEY_TITLE) or "").strip()
        message = content.get(KEY_MESSAGE) or ""
        fallback = SlackPayloadBuilder._fallback_text(title, message)

        payload = {"channel": channel, "text": fallback}
        if content_type == CONTENT_BLOCKS:
            payload["blocks"] = SlackPayloadBuilder._resolve_blocks(
                content, title, message
            )
        return payload

    @staticmethod
    def _fallback_text(title: str, message: str) -> str:
        if title and message:
            return f"{title}\n{message}"
        return title or message

    @staticmethod
    def _resolve_blocks(content: Dict, title: str, message: str) -> list:
        raw = (content.get(KEY_BLOCKS_JSON) or "").strip()
        if raw:
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Custom Block Kit JSON is not valid JSON: {exc}"
                ) from exc
            if not isinstance(parsed, list):
                raise ValueError(
                    "Custom Block Kit JSON must be a JSON array of block objects."
                )
            return parsed
        return SlackPayloadBuilder._default_blocks(title, message)

    @staticmethod
    def _default_blocks(title: str, message: str) -> list:
        blocks = []
        if title:
            blocks.append(
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": title[:_HEADER_MAX],
                        "emoji": True,
                    },
                }
            )
        blocks.append(
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": message[:_SECTION_TEXT_MAX]},
            }
        )
        return blocks
