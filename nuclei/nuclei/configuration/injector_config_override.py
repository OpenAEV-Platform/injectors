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
    author: str | None = Field(
        # Explicit author declaration (example of the override mechanism): the
        # value matches the injector's name here, which is also what the
        # platform would fall back to if the field were left unset.
        default="Nuclei",
        description="Author attributed to this injector's contracts. "
        "When unset, the platform attributes them to the injector's name.",
    )
    external_contracts_maintenance_schedule_seconds: int = Field(
        description="With every tick, trigger a maintenance of the external contracts (e.g. based on Nuclei templates)",
        default=86400,
    )
