from censys_injector.configuration.censys_config import CensysConfig
from censys_injector.configuration.injector_config_override import (
    InjectorConfigOverride,
)
from censys_injector.contracts_censys import CensysContracts
from pydantic import Field
from pyoaev.configuration import ConfigLoaderOAEV, Configuration, SettingsLoader


class ConfigLoader(SettingsLoader):
    openaev: ConfigLoaderOAEV = Field(default_factory=ConfigLoaderOAEV)
    injector: InjectorConfigOverride = Field(default_factory=InjectorConfigOverride)
    censys: CensysConfig = Field(default_factory=CensysConfig)

    def to_daemon_config(self) -> Configuration:
        return Configuration(
            config_hints={
                "openaev_url": {"data": str(self.openaev.url)},
                "openaev_token": {"data": self.openaev.token},
                "openaev_tenant_id": {"data": self.openaev.tenant_id},
                "injector_id": {"data": self.injector.id},
                "injector_name": {"data": self.injector.name},
                "injector_type": {"data": "openaev_censys"},
                "injector_contracts": {"data": CensysContracts.build_contract()},
                # Optional author override; None lets the platform attribute
                # the contracts to the injector's name.
                "injector_author": {"data": self.injector.author},
                "injector_log_level": {"data": self.injector.log_level},
                "injector_icon_filepath": {"data": self.injector.icon_filepath},
            },
            config_base_model=self,
        )
