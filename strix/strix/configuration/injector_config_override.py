from pydantic import Field
from pyoaev.configuration import ConfigLoaderCollector


class InjectorConfigOverride(ConfigLoaderCollector):
    id: str = Field(
        description="A unique UUIDv4 identifier for this injector instance.",
    )
    name: str = Field(
        default="Strix",
        description="Name of the injector.",
    )
    icon_filepath: str | None = Field(
        default="strix/img/strix.png",
        description="Path to the icon file",
    )
    author: str | None = Field(
        default="Strix",
        description="Author attributed to this injector's contracts. "
        "When unset, the platform attributes them to the injector's name.",
    )
    external_contracts_maintenance_schedule_seconds: int = Field(
        description="With every tick, trigger a maintenance of the external contracts.",
        default=86400,
    )
