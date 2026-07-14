from pydantic import Field
from pyoaev.configuration import ConfigLoaderCollector


class InjectorConfigOverride(ConfigLoaderCollector):
    id: str = Field(
        description="A unique UUIDv4 identifier for this injector instance.",
    )
    name: str = Field(
        default="Web Application Attack",
        description="Name of the injector.",
    )
    icon_filepath: str | None = Field(
        default="webapp_injector/img/icon-webapp.png",
        description="Path to the icon file",
    )
