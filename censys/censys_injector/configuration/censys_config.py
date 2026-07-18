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
        description="Number of results to request per page (Censys max: 100).",
    )
    max_pages: int = Field(
        default=10,
        description="Maximum number of result pages to follow via the Censys "
        "cursor before stopping (bounds API usage on broad queries).",
    )
