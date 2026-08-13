"""Configuration foundation for the Prowler injector."""

from pydantic import Field
from pyoaev.configuration import (
    ConfigLoaderCollector,
    ConfigLoaderOAEV,
    Configuration,
    SettingsLoader,
)


class InjectorConfig(ConfigLoaderCollector):
    """Standard injector identity and logging settings."""

    name: str = Field(default="Prowler", description="Name of the injector.")
    icon_filepath: str | None = Field(
        default=None, description="Optional path to an injector icon."
    )


class ConfigLoader(SettingsLoader):
    """Load only the standard OpenAEV and injector settings."""

    openaev: ConfigLoaderOAEV = Field(default_factory=ConfigLoaderOAEV)
    injector: InjectorConfig = Field(default_factory=InjectorConfig)

    def to_daemon_config(self) -> Configuration:
        """Translate settings into the OpenAEV daemon configuration."""
        return Configuration(
            config_hints={
                "openaev_url": {"data": str(self.openaev.url)},
                "openaev_token": {"data": self.openaev.token},
                "openaev_tenant_id": {"data": getattr(self.openaev, "tenant_id", None)},
                "injector_id": {"data": self.injector.id},
                "injector_name": {"data": self.injector.name},
                "injector_type": {"data": "openaev_prowler"},
                "injector_contracts": {"data": []},
                "injector_log_level": {"data": self.injector.log_level},
                "injector_icon_filepath": {"data": self.injector.icon_filepath},
            },
            config_base_model=self,
        )
