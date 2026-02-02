from pydantic import Field
from pyoaev.configuration import ConfigLoaderCollector


# To be change ConfigLoaderCollector
class InjectorConfigOverride(ConfigLoaderCollector):
    id: str = Field(
        description="A unique UUIDv4 identifier for this injector instance.",
    )
    name: str = Field(
        default="AWS",
        description="Name of the injector.",
    )
    icon_filepath: str | None = Field(
        default="aws/img/icon-aws.png",
        description="Path to the icon file",
    )
