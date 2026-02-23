from pydantic import Field
from pyoaev.configuration import ConfigLoaderOAEV, Configuration, SettingsLoader

from netexec.configuration.injector_config_override import InjectorConfigOverride
from netexec.contracts import build_all_contracts


class ConfigLoader(SettingsLoader):
    openaev: ConfigLoaderOAEV = Field(
        default_factory=ConfigLoaderOAEV, description="OpenAEV platform configuration"
    )
    injector: InjectorConfigOverride = Field(
        default_factory=InjectorConfigOverride,
        description="NetExec injector configuration",
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
                "injector_type": {"data": "openaev_netexec"},
                "injector_contracts": {"data": build_all_contracts()},
                "injector_log_level": {"data": self.injector.log_level},
                "injector_icon_filepath": {"data": self.injector.icon_filepath},
            },
            config_base_model=self,
        )
