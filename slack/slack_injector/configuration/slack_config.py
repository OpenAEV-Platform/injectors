"""Slack Web API credentials for the Slack injector.

The injector authenticates with a Slack **bot token** (``xoxb-...``) requested
once at app-install time, with the ``chat:write`` scope (and ``chat:write.public``
to post to public channels the bot has not joined). No per-inject credential is
needed - see the README for the app-creation steps.
"""

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings


class _ConfigLoaderSlack(BaseSettings):
    """Slack Web API configuration for the Slack injector."""

    bot_token: SecretStr = Field(
        description="Slack bot token (xoxb-...) with the chat:write scope.",
    )
    base_url: str = Field(
        default="https://slack.com/api",
        description="Base URL of the Slack Web API.",
    )
    request_timeout_seconds: int = Field(
        default=30,
        description="HTTP timeout (seconds) for a single Slack Web API request.",
    )
