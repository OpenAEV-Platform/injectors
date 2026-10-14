"""Injector runtime: registration, heartbeat and inject queue listening."""

import sched
import time
from typing import Callable, Dict

from xtm_oaev_sdk import BaseClient, OpenAEVError, PingAlive, logger

from injectors_sdk._core.helpers.config_helper import OpenAEVConfigHelper
from injectors_sdk._core.helpers.listen_queue import ListenQueue

__all__ = ["OpenAEVInjectorHelper"]


class OpenAEVInjectorHelper:
    """Registers the injector, keeps it alive and listens to its inject queue.

    :param api_client: an API client conforming to ``xtm_oaev_sdk.BaseClient``.
        When omitted, ``_create_default_api_client(config)`` builds it, which the
        SDK cannot do on its own: inject one, or override the hook.
    """

    def __init__(
        self,
        config: OpenAEVConfigHelper,
        icon,
        api_client: BaseClient | None = None,
    ) -> None:
        self.api = api_client or self._create_default_api_client(config)
        # Get the mq configuration from api
        self.config = {
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

        self.logger_class = logger(
            config.get_conf("injector_log_level", default="error").upper(),
            config.get_conf("injector_json_logging", default=True),
        )
        self.injector_logger = self.logger_class(config.get_conf("injector_name"))

        icon_name = config.get_conf("injector_type") + ".png"
        injector_icon = (icon_name, icon, "image/png")
        self.injector_config = self.api.injector.create(self.config, injector_icon)
        self.connect_run_and_terminate = False
        self.scheduler = sched.scheduler(time.time, time.sleep)
        # Start ping thread
        if not self.connect_run_and_terminate:
            self.ping = PingAlive(
                self.api, self.config, self.injector_logger, "injector"
            )
            self.ping.start()
        self.listen_queue = None

    def listen(self, message_callback: Callable[[Dict], None]) -> None:
        self.listen_queue = ListenQueue(
            self.config, self.injector_config, self.injector_logger, message_callback
        )
        self.listen_queue.start()

    def _create_default_api_client(self, config: OpenAEVConfigHelper) -> BaseClient:
        """Builds the API client used when none was injected. Client libraries
        override this hook (e.g. from the ``openaev_url``, ``openaev_token`` and
        ``openaev_tenant_id`` configuration keys).
        """
        raise OpenAEVError(
            "No api_client was provided to the injector; inject an OpenAEV API client."
        )
