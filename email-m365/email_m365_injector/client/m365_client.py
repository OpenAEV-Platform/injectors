"""Send email through the Microsoft Graph API (``POST /users/{sender}/sendMail``).

Authentication uses the OAuth2 client-credentials flow (app-only) via MSAL. The
Entra ID app must hold the ``Mail.Send`` application permission with admin
consent. A successful ``sendMail`` call returns HTTP 202 Accepted with an empty
body, so success is determined by the status code.
"""

from dataclasses import dataclass
from typing import Dict
from urllib.parse import quote

import msal
import requests
from requests.exceptions import RequestException, Timeout

DEFAULT_TIMEOUT = 30  # seconds
GRAPH_SCOPE = "https://graph.microsoft.com/.default"


@dataclass
class ExecutionResult:
    success: bool
    message: str

    @staticmethod
    def failure(message: str) -> "ExecutionResult":
        return ExecutionResult(success=False, message=message)


class M365Client:
    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        graph_base_url: str = "https://graph.microsoft.com/v1.0",
        authority_base_url: str = "https://login.microsoftonline.com",
        timeout: int = DEFAULT_TIMEOUT,
    ):
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret
        self._graph_base_url = graph_base_url.rstrip("/")
        self._authority = f"{authority_base_url.rstrip('/')}/{tenant_id}"
        self._timeout = timeout
        self._app = msal.ConfidentialClientApplication(
            client_id=self._client_id,
            authority=self._authority,
            client_credential=self._client_secret,
        )

    def _acquire_token(self) -> str:
        # A cached token is returned when still valid; otherwise a new one is minted.
        result = self._app.acquire_token_for_client(scopes=[GRAPH_SCOPE])
        token = result.get("access_token") if isinstance(result, dict) else None
        if not token:
            error = "unknown_error"
            if isinstance(result, dict):
                error = result.get("error_description") or result.get(
                    "error", "unknown_error"
                )
            raise RuntimeError(f"Failed to acquire Microsoft Graph token: {error}")
        return token

    def send_mail(
        self, sender: str, message: Dict, save_to_sent_items: bool = True
    ) -> ExecutionResult:
        try:
            token = self._acquire_token()
        except RuntimeError as exc:
            return ExecutionResult.failure(str(exc))

        url = f"{self._graph_base_url}/users/{quote(sender, safe='')}/sendMail"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        payload = {"message": message, "saveToSentItems": save_to_sent_items}
        try:
            response = requests.post(
                url, headers=headers, json=payload, timeout=self._timeout
            )
        except Timeout:
            return ExecutionResult.failure("Microsoft Graph request timed out")
        except RequestException as exc:
            return ExecutionResult.failure(f"Microsoft Graph request failed: {exc}")

        return self._to_result(response, sender)

    @staticmethod
    def _to_result(response, sender: str) -> ExecutionResult:
        # sendMail returns 202 Accepted with an empty body on success.
        if response.status_code == 202:
            return ExecutionResult(
                success=True,
                message=f"Email accepted by Microsoft Graph for {sender}",
            )

        error = M365Client._extract_error(response)
        return ExecutionResult.failure(
            f"Microsoft Graph API error (HTTP {response.status_code}): {error}"
        )

    @staticmethod
    def _extract_error(response) -> str:
        try:
            body = response.json()
        except ValueError:
            text = (response.text or "").strip()
            return text or "no response body"
        error = body.get("error") if isinstance(body, dict) else None
        if isinstance(error, dict):
            code = error.get("code", "")
            msg = error.get("message", "")
            return f"{code}: {msg}".strip(": ") or "unknown_error"
        return str(error) if error else "unknown_error"
