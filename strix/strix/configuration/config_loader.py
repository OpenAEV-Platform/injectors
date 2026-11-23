from pydantic import Field
from pyoaev.configuration import ConfigLoaderOAEV, Configuration, SettingsLoader

from strix.configuration.injector_config_override import InjectorConfigOverride
from strix.configuration.strix_configs import ConfigLoaderStrix
from strix.strix_contracts.strix_contracts import StrixContracts


class ConfigLoader(SettingsLoader):
    """Configuration loader for the injector."""

    openaev: ConfigLoaderOAEV = Field(
        default_factory=ConfigLoaderOAEV,
        description="Base OpenAEV configurations.",
    )
    injector: InjectorConfigOverride = Field(
        default_factory=InjectorConfigOverride,
        description="Base Injector configurations.",
    )
    strix: ConfigLoaderStrix = Field(
        default_factory=ConfigLoaderStrix,
        description="Strix configurations.",
    )

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
                "injector_type": {"data": "openaev_strix"},
                "injector_contracts": {
                    "data": StrixContracts.build_static_contracts()
                },
                "injector_author": {"data": self.injector.author},
                "injector_external_contracts_maintenance_schedule_seconds": {
                    "data": self.injector.external_contracts_maintenance_schedule_seconds
                },
                "injector_log_level": {"data": self.injector.log_level},
                "injector_icon_filepath": {"data": self.injector.icon_filepath},
            },
            config_base_model=self,
        )
