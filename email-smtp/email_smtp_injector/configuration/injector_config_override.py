from pydantic import Field
from pyoaev.configuration import ConfigLoaderCollector


class InjectorConfigOverride(ConfigLoaderCollector):
    id: str = Field(
        description="A unique UUIDv4 identifier for this injector instance.",
    )
    name: str = Field(
        description="Name of the injector.",
        default="Email (SMTP)",
    )
    icon_filepath: str | None = Field(
        description="Path to the icon file",
        default="email_smtp_injector/img/icon-email.png",
    )
    type: str = Field(
        description="Type of the injector.",
        default="openaev_email_smtp",
    )
    log_level: str = Field(
        description="Determines the verbosity of the logs. Options: debug, info, warn, or error.",
        default="info",
    )
