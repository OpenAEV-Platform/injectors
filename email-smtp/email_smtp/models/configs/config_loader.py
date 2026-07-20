"""Base class for global config models."""

from email_smtp.contracts.email_contracts import EmailContracts
from email_smtp.models.configs.injector_config_override import InjectorConfigOverride
from pydantic import Field
from pyoaev.configuration import ConfigLoaderOAEV, Configuration, SettingsLoader


class ConfigLoader(SettingsLoader):
    """Configuration loader for the injector."""

    openaev: ConfigLoaderOAEV = Field(
        default_factory=ConfigLoaderOAEV, description="Base OpenAEV configurations."
    )
    injector: InjectorConfigOverride = Field(
        default_factory=InjectorConfigOverride,
        description="Base Injector configurations.",
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
                "injector_type": {"data": self.injector.type},
                "injector_contracts": {"data": EmailContracts().contracts()},
                "injector_log_level": {"data": self.injector.log_level},
                "injector_icon_filepath": {"data": self.injector.icon_filepath},
            },
            config_base_model=self,
        )
