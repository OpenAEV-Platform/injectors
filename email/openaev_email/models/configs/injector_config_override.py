from typing import Literal

from pydantic import Field
from pydantic.json_schema import SkipJsonSchema
from pyoaev.configuration import ConfigLoaderCollector, Configuration

ICON_FILEPATH = "openaev_email/img/icon-email.png"


class InjectorConfigOverride(ConfigLoaderCollector):
    id: str = Field(
        description="A unique UUIDv4 identifier for this injector instance.",
    )
    name: str = Field(
        default="Email",
        description="Name of the injector.",
    )
    log_level: Literal["debug", "info", "warning", "error", "critical"] = Field(
        default="info",
        description=(
            "Determines the verbosity of the logs. "
            "Options: debug, info, warning, error, or critical."
        ),
    )
    icon_filepath: SkipJsonSchema[str] = Field(
        default=ICON_FILEPATH,
        description="Path to the icon file.",
    )

    def to_daemon_config(self) -> Configuration:
        return Configuration(  # ty: ignore[missing-argument]
            config_base_model=self,  # ty: ignore[invalid-argument-type]
        )
