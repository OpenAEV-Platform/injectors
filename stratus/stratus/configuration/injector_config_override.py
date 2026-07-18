from pydantic import Field
from pyoaev.configuration import ConfigLoaderCollector


class InjectorConfigOverride(ConfigLoaderCollector):
    id: str = Field(
        description="A unique UUIDv4 identifier for this injector instance.",
    )
    name: str = Field(
        default="Stratus Red Team",
        description="Name of the injector.",
    )
    icon_filepath: str | None = Field(
        default="stratus/img/icon-stratus.png",
        description="Path to the icon file",
    )
