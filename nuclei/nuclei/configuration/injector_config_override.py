from pydantic import Field
from pyoaev.configuration import ConfigLoaderCollector


# To be change ConfigLoaderCollector
class InjectorConfigOverride(ConfigLoaderCollector):
    id: str = Field(
        description="A unique UUIDv4 identifier for this injector instance.",
    )
    name: str = Field(
        default="Nuclei",
        description="Name of the injector.",
    )
    icon_filepath: str | None = Field(
        default="nuclei/img/nuclei.png",
        description="Path to the icon file",
    )
    type: str = Field(
        description="Type of the injector.",
        default="openaev_nuclei",
    )
    external_contracts_maintenance_schedule_seconds: int = Field(
        description="With every tick, trigger a maintenance of the external contracts (e.g. based on Nuclei templates)",
        default=86400,
    )
    log_level: str = Field(
        description="Determines the verbosity of the logs. Options: debug, info, warn, or error.",
        default="info",
    )
