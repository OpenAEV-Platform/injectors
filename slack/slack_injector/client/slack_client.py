"""Post messages to Slack through the Slack Web API (``chat.postMessage``).

Slack returns HTTP 200 even for logical failures, with an ``{"ok": false,
"error": "..."}`` envelope, so success is determined by the ``ok`` field rather
than the HTTP status code.
"""

from dataclasses import dataclass
from typing import Dict, Optional

import requests
from requests.exceptions import RequestException, Timeout

DEFAULT_TIMEOUT = 30  # seconds


@dataclass
class ExecutionResult:
    success: bool
    message: str
    channel: Optional[str] = None
    ts: Optional[str] = None

    @staticmethod
    def failure(message: str) -> "ExecutionResult":
        return ExecutionResult(success=False, message=message)


class SlackClient:
    def __init__(
        self,
        bot_token: str,
        base_url: str = "https://slack.com/api",
        timeout: int = DEFAULT_TIMEOUT,
    ):
        self._bot_token = bot_token
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout

    def post_message(self, payload: Dict) -> ExecutionResult:
        url = f"{self._base_url}/chat.postMessage"
        headers = {
            "Authorization": f"Bearer {self._bot_token}",
            "Content-Type": "application/json; charset=utf-8",
        }
        try:
            response = requests.post(
                url, headers=headers, json=payload, timeout=self._timeout
            )
        except Timeout:
            return ExecutionResult.failure("Slack request timed out")
        except RequestException as exc:
            return ExecutionResult.failure(f"Slack request failed: {exc}")

        return self._to_result(response)

    @staticmethod
    def _to_result(response) -> ExecutionResult:
        try:
            body = response.json()
        except ValueError:
            return ExecutionResult.failure(
                f"Slack returned a non-JSON response (HTTP {response.status_code})"
            )

        if body.get("ok"):
            return ExecutionResult(
                success=True,
                message="Slack message sent successfully",
                channel=body.get("channel"),
                ts=body.get("ts"),
            )

        error = body.get("error", "unknown_error")
        # Slack surfaces field-level issues in `response_metadata.messages`.
        details = body.get("response_metadata", {}).get("messages")
        detail_suffix = f" ({'; '.join(details)})" if details else ""
        return ExecutionResult.failure(f"Slack API error: {error}{detail_suffix}")
