"""Configuration for Shodan injector."""

from datetime import timedelta
from pydantic import (
    Field,
    SecretStr,
    PositiveInt,
)
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
    api_leaky_bucket_rate: PositiveInt = Field(
        default=10,
        description="Bucket refill rate (in tokens per second). Controls the rate at which API calls are allowed. "
                    "For example, a rate of 10 means that 10 calls can be made per second, if the bucket is not empty.",
    )
    api_leaky_bucket_capacity: PositiveInt = Field(
        default=10,
        description="Maximum bucket capacity (in tokens). Defines the number of calls that can be made immediately in a "
                    "burst. Once the bucket is empty, it refills at the rate defined by 'api_leaky_bucket_rate'.",
    )
    api_retry: PositiveInt = Field(
        default=5,
        description="Maximum number of attempts (including the initial request) in case of API failure.",
    )
    api_backoff: timedelta = Field(
        default="PT30S",
        description="Maximum exponential backoff delay between retry attempts (ISO 8601 duration format).",
    )