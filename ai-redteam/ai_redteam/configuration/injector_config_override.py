from pydantic import Field
from pyoaev.configuration import ConfigLoaderCollector


# NOTE: ConfigLoaderCollector is the shared connector config base reused by injectors today.
class InjectorConfigOverride(ConfigLoaderCollector):
    id: str = Field(
        description="A unique UUIDv4 identifier for this injector instance.",
    )
    name: str = Field(
        default="AI Red Team",
        description="Name of the injector.",
    )
    icon_filepath: str | None = Field(
        default="ai_redteam/img/icon-ai-redteam.png",
        description="Path to the icon file",
    )
    request_timeout_seconds: int = Field(
        default=120,
        description="HTTP timeout (seconds) for a single request to an AI target.",
    )
