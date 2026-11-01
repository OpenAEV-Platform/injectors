"""Send email through the Gmail API (``POST /users/me/messages/send``).

Authentication uses a Google Cloud service account with domain-wide delegation:
the service account impersonates a Workspace user (``with_subject``) and sends
as that user. A short-lived OAuth2 access token is minted per send via
google-auth. A successful call returns HTTP 200 with the created message
resource.
"""

import json
from dataclasses import dataclass

import google.auth.transport.requests
import requests
from google.oauth2 import service_account
from requests.exceptions import RequestException, Timeout

DEFAULT_TIMEOUT = 30  # seconds
GMAIL_SEND_SCOPE = "https://www.googleapis.com/auth/gmail.send"


@dataclass
class ExecutionResult:
    success: bool
    message: str

    @staticmethod
    def failure(message: str) -> "ExecutionResult":
        return ExecutionResult(success=False, message=message)


class GmailClient:
    def __init__(
        self,
        service_account_json: str,
        gmail_base_url: str = "https://gmail.googleapis.com/gmail/v1",
        timeout: int = DEFAULT_TIMEOUT,
    ):
        self._service_account_json = service_account_json
        self._gmail_base_url = gmail_base_url.rstrip("/")
        self._timeout = timeout

    def _acquire_token(self, subject: str) -> str:
        try:
            info = json.loads(self._service_account_json)
        except (ValueError, TypeError) as exc:
            raise RuntimeError(f"Invalid service account JSON: {exc}") from exc

        try:
            credentials = service_account.Credentials.from_service_account_info(
                info, scopes=[GMAIL_SEND_SCOPE], subject=subject
            )
            credentials.refresh(google.auth.transport.requests.Request())
        except Exception as exc:
            raise RuntimeError(f"Failed to acquire Gmail token: {exc}") from exc

        token = getattr(credentials, "token", None)
        if not token:
            raise RuntimeError("Failed to acquire Gmail token: empty token")
        return token

    def send_message(self, sender: str, raw_message: str) -> ExecutionResult:
        try:
            token = self._acquire_token(sender)
        except RuntimeError as exc:
            return ExecutionResult.failure(str(exc))

        url = f"{self._gmail_base_url}/users/me/messages/send"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        try:
            response = requests.post(
                url, headers=headers, json={"raw": raw_message}, timeout=self._timeout
            )
        except Timeout:
            return ExecutionResult.failure("Gmail request timed out")
        except RequestException as exc:
            return ExecutionResult.failure(f"Gmail request failed: {exc}")

        return self._to_result(response, sender)

    @staticmethod
    def _to_result(response, sender: str) -> ExecutionResult:
        if response.status_code == 200:
            message_id = ""
            try:
                body = response.json()
                if isinstance(body, dict):
                    message_id = body.get("id", "")
            except ValueError:
                pass
            suffix = f" (id={message_id})" if message_id else ""
            return ExecutionResult(
                success=True,
                message=f"Email sent through Gmail for {sender}{suffix}",
            )

        error = GmailClient._extract_error(response)
        return ExecutionResult.failure(
            f"Gmail API error (HTTP {response.status_code}): {error}"
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
            status = error.get("status", "")
            message = error.get("message", "")
            return f"{status}: {message}".strip(": ") or "unknown_error"
        return str(error) if error else "unknown_error"
