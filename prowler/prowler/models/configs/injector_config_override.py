"""Standard injector identity settings shared by OpenAEV injectors."""

from pydantic import Field
from pyoaev.configuration import ConfigLoaderCollector


class InjectorConfigOverride(ConfigLoaderCollector):
    """Standard injector identity and logging settings."""

    id: str = Field(
        description="A unique UUIDv4 identifier for this injector instance.",
    )
    name: str = Field(
        default="Prowler",
        description="Name of the injector.",
    )
    icon_filepath: str | None = Field(
        default="prowler/img/icon-prowler.png",
        description="Path to the icon file",
    )
    author: str | None = Field(
        default=None,
        description="Optional author override for this injector's contracts. "
        "When absent, the platform attributes them to the injector's name.",
    )
