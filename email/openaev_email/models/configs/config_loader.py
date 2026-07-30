"""Base class for global config models."""

from openaev_email.contracts.email_contracts import TYPE, EmailContracts
from openaev_email.models.configs.email_configs import ConfigLoaderEmail
from openaev_email.models.configs.injector_config_override import (
    ICON_FILEPATH,
    InjectorConfigOverride,
)
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
    email: ConfigLoaderEmail = Field(
        default_factory=ConfigLoaderEmail,
        description="Email configurations.",
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
                "injector_type": {"data": TYPE},
                "injector_contracts": {"data": EmailContracts().contracts()},
                "injector_log_level": {"data": self.injector.log_level},
                "injector_icon_filepath": {"data": ICON_FILEPATH},
                "email_hash_algorithm": {"data": self.email.hash_algorithm},
            },
            config_base_model=self,
        )
