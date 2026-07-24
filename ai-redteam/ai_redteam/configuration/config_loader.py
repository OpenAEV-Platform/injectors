from ai_redteam.configuration.injector_config_override import InjectorConfigOverride
from ai_redteam.contracts import constants as c
from ai_redteam.contracts.ai_contracts import build_contracts
from pydantic import Field
from pyoaev.configuration import ConfigLoaderOAEV, Configuration, SettingsLoader


class ConfigLoader(SettingsLoader):
    openaev: ConfigLoaderOAEV = Field(default_factory=ConfigLoaderOAEV)
    injector: InjectorConfigOverride = Field(default_factory=InjectorConfigOverride)

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
                "injector_type": {"data": c.INJECTOR_TYPE},
                "injector_contracts": {"data": build_contracts()},
                # Optional author override; None lets the platform attribute
                # the contracts to the injector's name.
                "injector_author": {"data": self.injector.author},
                "injector_log_level": {"data": self.injector.log_level},
                "injector_icon_filepath": {"data": self.injector.icon_filepath},
                "injector_request_timeout_seconds": {
                    "data": self.injector.request_timeout_seconds,
                    "is_number": True,
                },
            },
            config_base_model=self,
        )
