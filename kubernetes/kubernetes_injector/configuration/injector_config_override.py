from pydantic import Field
from pyoaev.configuration import ConfigLoaderCollector


class InjectorConfigOverride(ConfigLoaderCollector):
    id: str = Field(
        description="A unique UUIDv4 identifier for this injector instance.",
    )
    name: str = Field(
        default="Kubernetes",
        description="Name of the injector.",
    )
    icon_filepath: str | None = Field(
        default="kubernetes_injector/img/icon-kubernetes.png",
        description="Path to the icon file",
    )
