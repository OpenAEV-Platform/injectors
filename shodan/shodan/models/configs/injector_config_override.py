from pydantic import Field
from pyoaev.configuration import ConfigLoaderCollector, Configuration


# To be change ConfigLoaderCollector
class InjectorConfigOverride(ConfigLoaderCollector):
    id: str = Field(
        description="A unique UUIDv4 identifier for this injector instance.",
    )
    name: str = Field(
        default="Shodan",
        description="Name of the injector.",
    )
    icon_filepath: str | None = Field(
        default="shodan/img/icon-shodan.png",
        description="Path to the icon file",
    )

    def to_daemon_config(self) -> Configuration:
        return Configuration(
            config_base_model=self,
        )
