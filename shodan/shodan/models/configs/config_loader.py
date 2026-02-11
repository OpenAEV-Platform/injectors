"""Base class for global config models."""

from pydantic import BaseModel, Field
from pyoaev.configuration import ConfigLoaderOAEV, Configuration, SettingsLoader

from shodan.contracts.shodan_contracts import ShodanContracts
from shodan.models.configs import _ConfigLoaderShodan
from shodan.models.configs.injector_config_override import InjectorConfigOverride


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
            config_hints={
                # OpenAEV configuration (flattened)
                "openaev_url": {"data": str(self.openaev.url)},
                "openaev_token": {"data": self.openaev.token},
                # Injector configuration (flattened)
                "injector_id": {"data": self.injector.id},
                "injector_name": {"data": self.injector.name},
                "injector_type": {"data": "openaev_shodan"},
                "injector_contracts": {"data": ShodanContracts().contracts()},
                "injector_log_level": {"data": self.injector.log_level},
                "injector_icon_filepath": {"data": self.injector.icon_filepath},
            },
            config_base_model=self,
        )
