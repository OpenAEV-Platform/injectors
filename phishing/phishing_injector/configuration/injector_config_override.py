from pydantic import Field
from pyoaev.configuration import ConfigLoaderCollector


class InjectorConfigOverride(ConfigLoaderCollector):
    id: str = Field(
        description="A unique UUIDv4 identifier for this injector instance.",
    )
    name: str = Field(
        default="Phishing",
        description="Name of the injector.",
    )
    icon_filepath: str | None = Field(
        default="phishing_injector/img/icon-phishing.png",
        description="Path to the icon file",
    )
