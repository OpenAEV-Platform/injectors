"""Microsoft Graph credentials for the Teams injector.

Microsoft Graph does NOT allow sending Teams channel/chat messages with an
application-only (client-credentials) token: the only application permission for
that endpoint is ``Teamwork.Migrate.All``, which only works on channels in
migration mode. Real-time message sending requires DELEGATED permissions
(``ChannelMessage.Send`` / ``ChatMessage.Send``) with a user context.

To stay unattended while still using a confidential app (client id + secret), the
injector uses the OAuth2 refresh-token grant: an administrator performs a
one-time interactive consent to mint a long-lived refresh token (see the README),
and the injector silently exchanges it for short-lived access tokens at runtime.
"""

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings


class _ConfigLoaderTeams(BaseSettings):
    """Microsoft Entra ID / Graph configuration for the Teams injector."""

    tenant_id: str = Field(
        description="Directory (tenant) ID of the Microsoft Entra ID app registration.",
    )
    client_id: str = Field(
        description="Application (client) ID of the Microsoft Entra ID app registration.",
    )
    client_secret: SecretStr = Field(
        description="Client secret of the Microsoft Entra ID app registration.",
    )
    refresh_token: SecretStr = Field(
        description="Long-lived OAuth2 refresh token obtained from the one-time admin "
        "consent flow (see the README). Exchanged for Graph access tokens at runtime.",
    )
    authority_base_url: str = Field(
        default="https://login.microsoftonline.com",
        description="Microsoft identity platform base URL (override for sovereign/national clouds).",
    )
    graph_base_url: str = Field(
        default="https://graph.microsoft.com/v1.0",
        description="Microsoft Graph base URL (override for sovereign/national clouds).",
    )
    scope: str = Field(
        default="offline_access ChannelMessage.Send ChatMessage.Send",
        description="Space-separated delegated Graph scopes requested during the token exchange.",
    )
    request_timeout_seconds: int = Field(
        default=30,
        description="HTTP timeout (seconds) for a single Microsoft Graph or token request.",
    )
