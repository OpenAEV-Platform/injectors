from typing import Literal

from pydantic import Field
from pyoaev.configuration import ConfigLoaderCollector


# To be change ConfigLoaderCollector
class InjectorConfigOverride(ConfigLoaderCollector):
    id: str = Field(
        description="A unique UUIDv4 identifier for this injector instance.",
    )
    name: str = Field(
        description="Name of the injector.",
        default="NetExec",
    )
    icon_filepath: str = Field(
        description="Path to the icon file",
        default="netexec/img/icon-netexec.png",
    )
    log_level: Literal["debug", "info", "warn", "error"] = Field(
        description="Determines the verbosity of the logs. Options: debug, info, warn, or error.",
        default="info",
    )
