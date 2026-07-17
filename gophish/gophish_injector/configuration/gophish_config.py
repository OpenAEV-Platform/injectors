from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings


class GophishConfig(BaseSettings):
    """Gophish server connection settings."""

    base_url: str = Field(
        default="https://localhost:3333",
        description="Base URL of the Gophish admin server.",
    )
    api_key: SecretStr = Field(
        description="Gophish API key (Settings page).",
    )
    verify_tls: bool = Field(
        default=True,
        description=(
            "Verify the Gophish server TLS certificate. Secure by default; set "
            "to false only for self-signed or local development servers."
        ),
    )
