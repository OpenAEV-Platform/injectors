"""Acquire Microsoft Graph delegated access tokens without user interaction.

Sending Teams messages requires DELEGATED permissions, so the injector cannot use
the client-credentials (app-only) grant. Instead it uses the OAuth2 refresh-token
grant: a one-time admin consent (see the README) yields a long-lived refresh
token, which this provider silently exchanges for short-lived access tokens.

Entra ID rotates the refresh token on every exchange, so the newest refresh token
is kept in memory for the lifetime of the process. Access tokens are cached until
shortly before they expire to avoid a token request on every inject.
"""

import time

import requests


class GraphAuthError(RuntimeError):
    """Raised when a Microsoft Graph access token cannot be acquired."""


class GraphTokenProvider:
    # Refresh a little early so a token never expires mid-request.
    _EXPIRY_SKEW_SECONDS = 60

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        refresh_token: str,
        authority_base_url: str = "https://login.microsoftonline.com",
        scope: str = "offline_access ChannelMessage.Send ChatMessage.Send",
        timeout: int = 30,
    ):
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret
        self._refresh_token = refresh_token
        self._authority_base_url = authority_base_url.rstrip("/")
        self._scope = scope
        self._timeout = timeout
        self._access_token = None
        self._expires_at = 0.0

    @property
    def token_url(self) -> str:
        return f"{self._authority_base_url}/{self._tenant_id}/oauth2/v2.0/token"

    def get_access_token(self) -> str:
        if self._access_token and time.time() < self._expires_at:
            return self._access_token
        return self._refresh()

    def _refresh(self) -> str:
        data = {
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "grant_type": "refresh_token",
            "refresh_token": self._refresh_token,
            "scope": self._scope,
        }
        try:
            response = requests.post(self.token_url, data=data, timeout=self._timeout)
        except requests.RequestException as exc:
            raise GraphAuthError(
                f"Failed to reach the Microsoft identity platform: {exc}"
            ) from exc

        payload = {}
        try:
            payload = response.json()
        except ValueError:
            pass

        if response.status_code != 200 or "access_token" not in payload:
            error = payload.get("error", f"HTTP {response.status_code}")
            description = payload.get("error_description", response.text)
            raise GraphAuthError(
                f"Microsoft Graph token request failed ({error}): {description}"
            )

        # Entra ID rotates the refresh token on each exchange; keep the latest one.
        if payload.get("refresh_token"):
            self._refresh_token = payload["refresh_token"]

        self._access_token = payload["access_token"]
        expires_in = int(payload.get("expires_in", 3600))
        self._expires_at = time.time() + max(expires_in - self._EXPIRY_SKEW_SECONDS, 0)
        return self._access_token
