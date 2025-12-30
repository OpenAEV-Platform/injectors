from typing import List

from pydantic import Field, SecretStr
from pyoaev.configuration import ConfigLoaderCollector
from pyoaev.contracts.contract_config import Contract


# To be change ConfigLoaderCollector
class InjectorConfigOverride(ConfigLoaderCollector):
    id: str = Field(
        description="A unique UUIDv4 identifier for this injector instance.",
    )
    name: str = Field(
        default="Nmap",
        description="Name of the injector.",
    )
    icon_filepath: str | None = Field(
        default="nmap/img/nmap.png",
        description="Path to the icon file",
    )
    type: str = Field(
        description="Type of the injector.",
        default="openaev_nmap",
    )
    log_level: str = Field(
        description="Determines the verbosity of the logs. Options: debug, info, warn, or error.",
        default="info",
    )
