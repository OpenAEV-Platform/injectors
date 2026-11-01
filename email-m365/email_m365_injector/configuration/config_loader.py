from email_m365_injector.configuration.injector_config_override import (
    InjectorConfigOverride,
)
from email_m365_injector.configuration.m365_config import _ConfigLoaderM365
from email_m365_injector.contracts_email_m365 import EmailM365Contracts
from pydantic import Field
from pyoaev.configuration import ConfigLoaderOAEV, Configuration, SettingsLoader


class ConfigLoader(SettingsLoader):
    openaev: ConfigLoaderOAEV = Field(default_factory=ConfigLoaderOAEV)
    injector: InjectorConfigOverride = Field(default_factory=InjectorConfigOverride)
    m365: _ConfigLoaderM365 = Field(default_factory=_ConfigLoaderM365)

    def to_daemon_config(self) -> Configuration:
        return Configuration(
            config_hints={
                # OpenAEV configuration (flattened)
                "openaev_url": {"data": str(self.openaev.url)},
                "openaev_token": {"data": self.openaev.token},
                "openaev_tenant_id": {"data": self.openaev.tenant_id},
                # Injector configuration (flattened)
                "injector_id": {"data": self.injector.id},
                "injector_name": {"data": self.injector.name},
                "injector_type": {"data": self.injector.type},
                "injector_contracts": {"data": EmailM365Contracts.build()},
                # Optional author override; None lets the platform attribute
                # the contracts to the injector's name.
                "injector_author": {"data": self.injector.author},
                "injector_log_level": {"data": self.injector.log_level},
                "injector_icon_filepath": {"data": self.injector.icon_filepath},
            },
            config_base_model=self,
        )
