from pydantic import Field
from pyoaev.configuration import ConfigLoaderCollector


class InjectorConfigOverride(ConfigLoaderCollector):
    id: str = Field(
        description="A unique UUIDv4 identifier for this injector instance.",
    )
    name: str = Field(
        description="Name of the injector.",
        default="Email",
    )
    icon_filepath: str | None = Field(
        description="Path to the icon file",
        default="email_injector/img/icon-email.png",
    )
    type: str = Field(
        description="Type of the injector.",
        default="openaev_email",
    )
    log_level: str = Field(
        description="Determines the verbosity of the logs. Options: debug, info, warn, or error.",
        default="info",
    )
    smtp_hostname: str = Field(
        description="Hostname of the SMTP server used to send emails.",
    )
    smtp_port: int = Field(
        description="Port of the SMTP server used to send emails.",
        default=587,
    )
    smtp_use_tls: bool = Field(
        description="Whether to use STARTTLS when connecting to the SMTP server.",
        default=False,
    )
    smtp_username: str | None = Field(
        description="Username used to authenticate against the SMTP server.",
        default=None,
    )
    smtp_password: str | None = Field(
        description="Password used to authenticate against the SMTP server.",
        default=None,
    )
