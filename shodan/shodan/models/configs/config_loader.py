"""Base class for global config models."""

from pydantic import BaseModel, Field
from pydantic_settings import (
    BaseSettings,
    DotEnvSettingsSource,
    EnvSettingsSource,
    PydanticBaseSettingsSource,
    YamlConfigSettingsSource,
)
from pyoaev.configuration import ConfigLoaderOAEV, Configuration, SettingsLoader

from shodan.models.configs import _ConfigLoaderShodan
from shodan.models.configs.injector_config_override import InjectorConfigOverride


class _BaseInjectorConfigHelperAdapter:
    def __init__(self, data: dict):
        self.data = data

    def get_conf(self, key, default=None):
        value = self.data.get(key, default)
        if isinstance(value, dict) and "data" in value:
            value = value["data"]
        return value


class _BaseInjectorConfigUtils:

    def to_flatten(self, contracts=None) -> dict:
        flatten_config = {}
        for field_name in ["openaev", "injector"]:
            value = getattr(self, field_name, None)
            if isinstance(value, BaseModel):
                for subfield, subvalue in value.__dict__.items():
                    flatten_config[f"{field_name}_{subfield}"] = str(subvalue)
            elif value is not None:
                flatten_config[field_name] = str(value)
            if contracts:
                flatten_config["injector_contracts"] = contracts
        return flatten_config

    def to_config_injector_helper_adapter(
        self, contracts
    ) -> _BaseInjectorConfigHelperAdapter:
        """Returns an OpenAEVInjectorHelper-compatible object"""
        flatten_dict = self.to_flatten(contracts)
        return _BaseInjectorConfigHelperAdapter(flatten_dict)


class ConfigLoader(SettingsLoader):
    """Configuration loader for the injector."""

    openaev: ConfigLoaderOAEV = Field(
        default_factory=ConfigLoaderOAEV, description="Base OpenAEV configurations."
    )
    injector: InjectorConfigOverride = Field(
        default_factory=InjectorConfigOverride,
        description="Base Injector configurations.",
    )
    shodan: _ConfigLoaderShodan = Field(
        default_factory=_ConfigLoaderShodan,
        description="Shodan configurations.",
    )

    def to_daemon_config(self) -> Configuration:
        return Configuration(
            config_hints={},
            config_base_model=self,
        )
