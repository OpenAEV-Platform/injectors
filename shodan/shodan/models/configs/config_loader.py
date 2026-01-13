"""Base class for global config models."""
from pathlib import Path
from pydantic import Field, BaseModel

from pydantic_settings import (
    BaseSettings,
    DotEnvSettingsSource,
    EnvSettingsSource,
    PydanticBaseSettingsSource,
    YamlConfigSettingsSource,
)

from shodan.models.configs import (
    _SettingsLoader,
    _BaseOpenAEVConfig,
    _BaseInjectorConfig,
    _ConfigLoaderShodan,
)

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

    def to_config_injector_helper_adapter(self, contracts) -> _BaseInjectorConfigHelperAdapter:
        """Returns an OpenAEVInjectorHelper-compatible object"""
        flatten_dict = self.to_flatten(contracts)
        return _BaseInjectorConfigHelperAdapter(flatten_dict)


class ConfigLoader(_BaseInjectorConfigUtils, _SettingsLoader):
    """Configuration loader for the injector."""

    openaev: _BaseOpenAEVConfig = Field(
        default_factory=_BaseOpenAEVConfig,
        description="Base OpenAEV configurations.",
    )
    injector: _BaseInjectorConfig = Field(
        default_factory=_BaseInjectorConfig,
        description="Base Injector configurations.",
    )
    shodan: _ConfigLoaderShodan = Field(
        default_factory=_ConfigLoaderShodan,
        description="Shodan configurations.",
    )

    @classmethod
    def settings_customise_sources(
            cls,
            settings_cls: type[BaseSettings],
            init_settings: PydanticBaseSettingsSource,
            env_settings: PydanticBaseSettingsSource,
            dotenv_settings: PydanticBaseSettingsSource,
            file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource]:
        """Pydantic settings customisation sources.

        Defines the priority order for loading configuration settings:
        1. .env file (if exists)
        2. config.yml file (if exists)
        3. Environment variables (fallback)

        Args:
            settings_cls: The settings class being configured.
            init_settings: Initialization settings source.
            env_settings: Environment variables settings source.
            dotenv_settings: .env file settings source.
            file_secret_settings: File secrets settings source.

        Returns:
            Tuple containing the selected settings source.

        """
        env_path = Path(__file__).parents[2] / ".env"
        yaml_path = Path(__file__).parents[2] / "config.yml"

        if env_path.exists():
            return (
                DotEnvSettingsSource(
                    settings_cls,
                    env_file=env_path,
                    env_ignore_empty=True,
                    env_file_encoding="utf-8",
                ),
            )
        elif yaml_path.exists():
            return (
                YamlConfigSettingsSource(
                    settings_cls,
                    yaml_file=yaml_path,
                    yaml_file_encoding="utf-8",
                ),
            )
        else:
            return (
                EnvSettingsSource(
                    settings_cls,
                    env_ignore_empty=True,
                ),
            )