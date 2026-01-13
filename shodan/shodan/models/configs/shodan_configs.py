"""Configuration for Shodan injector."""

from pydantic import Field, SecretStr
from shodan.models.configs import _SettingsLoader


class _ConfigLoaderShodan(_SettingsLoader):
    """Shodan API configuration settings."""

    base_url: str = Field(
        default="https://api.shodan.io",
        description="This is the base URL for the Shodan API.",
    )
    api_key: SecretStr = Field(
        description="This is the API key for the Shodan API.",
    )