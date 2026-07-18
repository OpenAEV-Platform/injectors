"""Post messages to Microsoft Teams through the Microsoft Graph API.

Channel messages: ``POST /teams/{team-id}/channels/{channel-id}/messages``
Chat messages:    ``POST /chats/{chat-id}/messages``

Both endpoints require a delegated access token (see ``graph_auth``). The request
body is built by :class:`teams.helpers.teams_helper.TeamsPayloadBuilder`.
"""

from dataclasses import dataclass
from typing import Dict, Optional

import requests
from requests.exceptions import RequestException, Timeout

from teams.client.graph_auth import GraphAuthError, GraphTokenProvider

DEFAULT_TIMEOUT = 30  # seconds


@dataclass
class ExecutionResult:
    success: bool
    message: str
    status_code: int = 0
    message_id: Optional[str] = None
    web_url: Optional[str] = None

    @staticmethod
    def failure(message: str, status_code: int = 0) -> "ExecutionResult":
        return ExecutionResult(success=False, message=message, status_code=status_code)


class TeamsClient:
    def __init__(
        self,
        token_provider: GraphTokenProvider,
        graph_base_url: str = "https://graph.microsoft.com/v1.0",
        timeout: int = DEFAULT_TIMEOUT,
    ):
        self._token_provider = token_provider
        self._graph_base_url = graph_base_url.rstrip("/")
        self._timeout = timeout

    def post_channel_message(
        self, team_id: str, channel_id: str, body: Dict
    ) -> ExecutionResult:
        url = f"{self._graph_base_url}/teams/{team_id}/channels/{channel_id}/messages"
        return self._post(url, body, "Teams channel message")

    def post_chat_message(self, chat_id: str, body: Dict) -> ExecutionResult:
        url = f"{self._graph_base_url}/chats/{chat_id}/messages"
        return self._post(url, body, "Teams chat message")

    def _post(self, url: str, body: Dict, label: str) -> ExecutionResult:
        try:
            access_token = self._token_provider.get_access_token()
        except GraphAuthError as exc:
            return ExecutionResult.failure(str(exc))

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }
        try:
            response = requests.post(
                url, headers=headers, json=body, timeout=self._timeout
            )
        except Timeout:
            return ExecutionResult.failure(f"{label} request timed out")
        except RequestException as exc:
            return ExecutionResult.failure(f"{label} request failed: {exc}")

        return self._to_result(response, label)

    @staticmethod
    def _to_result(response, label: str) -> ExecutionResult:
        success = 200 <= response.status_code < 300
        payload = {}
        try:
            payload = response.json()
        except ValueError:
            pass

        if success:
            return ExecutionResult(
                success=True,
                message=f"{label} sent successfully",
                status_code=response.status_code,
                message_id=payload.get("id"),
                web_url=payload.get("webUrl"),
            )

        error = payload.get("error", {}) if isinstance(payload, dict) else {}
        detail = error.get("message") if isinstance(error, dict) else None
        detail = detail or (response.text or "").strip()
        return ExecutionResult.failure(
            f"{label} failed (HTTP {response.status_code}): {detail}",
            status_code=response.status_code,
        )
