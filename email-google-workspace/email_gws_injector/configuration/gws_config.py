"""Google Workspace / Gmail API credentials for the Email (Google Workspace) injector.

The injector authenticates to the Gmail API with a Google Cloud **service
account** key and **domain-wide delegation**: the service account impersonates a
Workspace user (the inject "from" address) and sends as that user. A Workspace
super admin must authorize the service account's client id for the
``https://www.googleapis.com/auth/gmail.send`` scope in the Admin console - see
the README.
"""

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings


class _ConfigLoaderGWS(BaseSettings):
    """Gmail API configuration for the Email (Google Workspace) injector."""

    service_account_json: SecretStr = Field(
        description=(
            "Full service account key JSON (the downloaded key file content) for a "
            "service account with domain-wide delegation for gmail.send."
        ),
    )
    gmail_base_url: str = Field(
        default="https://gmail.googleapis.com/gmail/v1",
        description="Base URL of the Gmail API.",
    )
    request_timeout_seconds: int = Field(
        default=30,
        description="HTTP timeout (seconds) for a single Gmail API request.",
    )
