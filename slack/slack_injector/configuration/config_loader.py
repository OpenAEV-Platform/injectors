from pydantic import Field
from pyoaev.configuration import ConfigLoaderOAEV, Configuration, SettingsLoader
from slack_injector.configuration.injector_config_override import (
    InjectorConfigOverride,
)
from slack_injector.configuration.slack_config import _ConfigLoaderSlack
from slack_injector.contracts_slack import SlackContracts


class ConfigLoader(SettingsLoader):
    openaev: ConfigLoaderOAEV = Field(default_factory=ConfigLoaderOAEV)
    injector: InjectorConfigOverride = Field(default_factory=InjectorConfigOverride)
    slack: _ConfigLoaderSlack = Field(default_factory=_ConfigLoaderSlack)

    def to_daemon_config(self) -> Configuration:
        return Configuration(
            config_hints={
                # OpenAEV configuration (flattened)
                "openaev_url": {"data": str(self.openaev.url)},
                "openaev_token": {"data": self.openaev.token},
                # Injector configuration (flattened)
                "injector_id": {"data": self.injector.id},
                "injector_name": {"data": self.injector.name},
                "injector_type": {"data": self.injector.type},
                "injector_contracts": {"data": SlackContracts.build()},
                # Optional author override; None lets the platform attribute
                # the contracts to the injector's name.
                "injector_author": {"data": self.injector.author},
                "injector_log_level": {"data": self.injector.log_level},
                "injector_icon_filepath": {"data": self.injector.icon_filepath},
            },
            config_base_model=self,
        )
