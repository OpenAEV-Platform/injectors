"""Base class for global config models."""

from abc import ABC
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
)


class BaseConfigModel(BaseModel, ABC):
    """Base class for global config models
    To prevent attributes from being modified after initialization.
    """

    model_config = ConfigDict(
        extra="allow", str_min_length=1, frozen=True, validate_default=True
    )


class _BaseOpenAEVConfig(BaseConfigModel, ABC):
    url: HttpUrl = Field(
        description="The base URL of the OpenAEV instance.",
    )
    token: str = Field(
        description="The API token to connect to OpenAEV.",
    )


class _BaseInjectorConfig(BaseConfigModel, ABC):
    """Base class for connector configuration."""

    id: str = Field(
        default="shodan--a87488ad-2c72-4592-b429-69259d7bcef1",
        description="A unique UUIDv4 identifier for this injector instance.",
    )
    name: str = Field(
        default="Shodan",
        description="Name of the injector.",
    )
    type: str = Field(
        default="openaev_shodan",
        description="Identifies the functional type of the injector in OpenAEV",
    )
    log_level: Literal["debug", "info", "warning", "error"] = Field(
        default="error",
        description="The minimum level of logs to display.",
    )
