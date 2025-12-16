"""Configuration for Shodan injector."""

from pydantic import Field, SecretStr
from shodan.models.configs import _SettingsLoader


class _ConfigLoaderShodan(_SettingsLoader):
    """Shodan API configuration settings."""

    base_url: str = Field(
        default="https://api.shodan.io",
        description="URL for the Shodan API.",
    )
    api_key: SecretStr = Field(
        description="API Key for the Shodan API.",
    )