"""Microsoft 365 / Microsoft Graph credentials for the Email (Microsoft 365) injector.

The injector authenticates to Microsoft Graph with an Entra ID (Azure AD)
application using the OAuth2 client-credentials flow (app-only). The app needs
the ``Mail.Send`` **application** permission with tenant admin consent. No
per-inject credential is required - see the README for the app-registration
steps.
"""

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings


class _ConfigLoaderM365(BaseSettings):
    """Microsoft Graph configuration for the Email (Microsoft 365) injector."""

    tenant_id: str = Field(
        description="Entra ID (Azure AD) tenant id (GUID) the app belongs to.",
    )
    client_id: str = Field(
        description="Application (client) id of the Entra ID app registration.",
    )
    client_secret: SecretStr = Field(
        description="Client secret of the Entra ID app registration.",
    )
    graph_base_url: str = Field(
        default="https://graph.microsoft.com/v1.0",
        description="Base URL of the Microsoft Graph API.",
    )
    authority_base_url: str = Field(
        default="https://login.microsoftonline.com",
        description="Base URL of the Microsoft identity platform (authority).",
    )
    request_timeout_seconds: int = Field(
        default=30,
        description="HTTP timeout (seconds) for a single Microsoft Graph request.",
    )
