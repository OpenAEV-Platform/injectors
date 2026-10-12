"""Configuration foundation for the Prowler injector."""

from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, Field, field_validator
from pyoaev.configuration import ConfigLoaderOAEV, Configuration, SettingsLoader

from prowler.models.configs.injector_config_override import InjectorConfigOverride


class ProwlerConfig(BaseModel):
    """Prowler command runtime settings."""

    executable_path: Path = Field(
        default=Path("/usr/local/bin/prowler"),
        description="Absolute path to the Prowler executable.",
    )

    @field_validator("executable_path", mode="before")
    @classmethod
    def validate_executable_path(cls, value: object) -> object:
        """Reject blank and non-absolute executable paths."""
        if isinstance(value, str) and not value.strip():
            raise ValueError("executable path must not be blank")
        if isinstance(value, (str, Path)) and not Path(value).is_absolute():
            raise ValueError("executable path must be absolute")
        return value


class ContractRegistryPort(Protocol):
    """Provide prepared contracts without coupling settings to registry internals."""

    def contracts(self) -> list[dict[str, object]]:
        """Return pyoaev-prepared concrete contracts."""


class ConfigLoader(SettingsLoader):
    """Load standard settings and the Prowler runtime section."""

    openaev: ConfigLoaderOAEV = Field(
        default_factory=ConfigLoaderOAEV, description="Base OpenAEV configurations."
    )
    injector: InjectorConfigOverride = Field(
        default_factory=InjectorConfigOverride,
        description="Base Injector configurations.",
    )
    prowler: ProwlerConfig = Field(default_factory=ProwlerConfig)

    def to_daemon_config(
        self, registry: ContractRegistryPort | None = None
    ) -> Configuration:
        """Translate settings into the OpenAEV daemon configuration."""
        if registry is None:
            from prowler.contracts import DEFAULT_PROWLER_CONTRACTS

            registry = DEFAULT_PROWLER_CONTRACTS
        contracts = registry.contracts()
        return Configuration(
            config_hints={
                "openaev_url": {"data": str(self.openaev.url)},
                "openaev_token": {"data": self.openaev.token},
                "openaev_tenant_id": {"data": self.openaev.tenant_id},
                "injector_id": {"data": self.injector.id},
                "injector_name": {"data": self.injector.name},
                "injector_type": {"data": "openaev_prowler"},
                "injector_contracts": {"data": contracts},
                # Optional author override; None lets the platform attribute
                # the contracts to the injector's name.
                "injector_author": {"data": self.injector.author},
                "injector_log_level": {"data": self.injector.log_level},
                "injector_icon_filepath": {"data": self.injector.icon_filepath},
                "prowler_executable_path": {"data": str(self.prowler.executable_path)},
            },
            config_base_model=self,
        )
