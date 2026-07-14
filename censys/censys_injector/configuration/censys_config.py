from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings


class CensysConfig(BaseSettings):
    """Censys Search API credentials and settings."""

    base_url: str = Field(
        default="https://search.censys.io",
        description="Base URL for the Censys Search API.",
    )
    api_id: SecretStr = Field(
        description="Censys Search API ID.",
    )
    api_secret: SecretStr = Field(
        description="Censys Search API secret.",
    )
    per_page: int = Field(
        default=50,
        description="Maximum number of results to request per search.",
    )
