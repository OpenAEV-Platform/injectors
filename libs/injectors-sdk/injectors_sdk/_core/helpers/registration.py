"""Injector registration: the injector record, its logging and its icon."""

import sched
import time
from typing import Any

from xtm_oaev_sdk import BaseClient, OpenAEVError

__all__ = ["InjectorRegistration"]


class InjectorRegistration:
    """Implements ``InjectorRegistrationPort``."""

    def injector_config(self, config: Any) -> dict[str, Any]:
        # Get the mq configuration from api
        return {
            "injector_id": config.get_conf("injector_id"),
            "injector_name": config.get_conf("injector_name"),
            "injector_type": config.get_conf("injector_type"),
            "injector_contracts": config.get_conf("injector_contracts"),
            "injector_custom_contracts": config.get_conf(
                "injector_custom_contracts", default=False
            ),
            "injector_category": config.get_conf("injector_category", default=None),
            "injector_executor_commands": config.get_conf(
                "injector_executor_commands", default=None
            ),
            "injector_executor_clear_commands": config.get_conf(
                "injector_executor_clear_commands", default=None
            ),
            # Publisher/author of the injector's contracts (source-declared).
            "injector_author": config.get_conf("injector_author", default=None),
        }

    def logger_settings(self, config: Any) -> tuple[Any, Any]:
        return (
            config.get_conf("injector_log_level", default="error").upper(),
            config.get_conf("injector_json_logging", default=True),
        )

    def icon(self, config: Any, icon: Any) -> tuple[str, Any, str]:
        icon_name = config.get_conf("injector_type") + ".png"
        return (icon_name, icon, "image/png")

    def register(
        self, api: Any, injector_config: dict[str, Any], injector_icon: Any
    ) -> Any:
        return api.injector.create(injector_config, injector_icon)

    def scheduler(self) -> sched.scheduler:
        return sched.scheduler(time.time, time.sleep)

    def default_api_client(self) -> BaseClient:
        raise OpenAEVError(
            "No api_client was provided to the injector; inject an OpenAEV API client."
        )
