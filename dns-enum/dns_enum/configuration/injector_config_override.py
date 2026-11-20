from pydantic import Field
from pyoaev.configuration import ConfigLoaderCollector


class InjectorConfigOverride(ConfigLoaderCollector):
    id: str = Field(
        description="A unique UUIDv4 identifier for this injector instance.",
    )
    name: str = Field(
        default="DNS Enumeration",
        description="Name of the injector.",
    )
    icon_filepath: str | None = Field(
        default="dns_enum/img/icon-dns-enum.png",
        description="Path to the icon file",
    )
    author: str | None = Field(
        default=None,
        description="Author attributed to this injector's contracts. "
        "When unset, the platform attributes them to the injector's name.",
    )
