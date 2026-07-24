from pydantic import Field
from pyoaev.configuration import ConfigLoaderCollector


class InjectorConfigOverride(ConfigLoaderCollector):
    id: str = Field(
        description="A unique UUIDv4 identifier for this injector instance.",
    )
    name: str = Field(
        description="Name of the injector.",
        default="Email (Microsoft 365)",
    )
    icon_filepath: str | None = Field(
        description="Path to the icon file",
        default="email_m365_injector/img/icon-email-m365.png",
    )
    type: str = Field(
        description="Type of the injector.",
        default="openaev_email_m365",
    )
    log_level: str = Field(
        description="Determines the verbosity of the logs. Options: debug, info, warn, or error.",
        default="info",
    )
    author: str | None = Field(
        default=None,
        description="Optional author override for this injector's contracts. "
        "When absent, the platform attributes them to the injector's name.",
    )
