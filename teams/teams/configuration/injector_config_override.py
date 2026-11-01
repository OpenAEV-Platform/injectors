from pydantic import Field
from pyoaev.configuration import ConfigLoaderCollector


# To be change ConfigLoaderCollector
class InjectorConfigOverride(ConfigLoaderCollector):
    id: str = Field(
        description="A unique UUIDv4 identifier for this injector instance.",
    )
    name: str = Field(
        description="Name of the injector.",
        default="Microsoft Teams",
    )
    icon_filepath: str | None = Field(
        description="Path to the icon file",
        default="teams/img/icon-teams.png",
    )
    type: str = Field(
        description="Type of the injector.",
        default="openaev_teams",
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
