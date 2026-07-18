from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings


class PhishingConfig(BaseSettings):
    """Embedded tracking server and SMTP relay settings."""

    public_url: str = Field(
        default="http://localhost:8080",
        description="Publicly reachable base URL of the embedded tracking server "
        "(targets must be able to reach it).",
    )
    listen_host: str = Field(
        default="0.0.0.0",
        description="Bind address for the embedded tracking server.",
    )
    listen_port: int = Field(
        default=8080,
        description="Listen port for the embedded tracking server.",
    )
    redirect_url: str = Field(
        default="https://www.office.com/",
        description="Where recipients are redirected after submitting.",
    )
    smtp_host: str = Field(default="localhost", description="SMTP relay host.")
    smtp_port: int = Field(default=587, description="SMTP relay port.")
    smtp_username: str | None = Field(default=None, description="SMTP username.")
    smtp_password: SecretStr | None = Field(default=None, description="SMTP password.")
    smtp_use_tls: bool = Field(default=True, description="Use STARTTLS.")
    mail_from: str = Field(
        default="it-support@example.com",
        description="From address for phishing emails.",
    )
