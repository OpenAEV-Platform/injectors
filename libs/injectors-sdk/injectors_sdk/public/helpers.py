"""Injector helper adapters: configuration access, registration, heartbeat and
inject queue listening.

Each adapter speaks the helpers seam types and delegates to the core
implementation of its port. The API client is injected (``BaseClient``).
"""

import ssl
import threading
from typing import Callable, Dict

from injectors_sdk._core.helpers import (
    ConfigLookup,
    InjectorRegistration,
    MqSsl,
    QueueConsumer,
)
from injectors_sdk.seam.helpers import (
    ConfigLookupPort,
    InjectorRegistrationPort,
    MqSslPort,
    QueueConsumerPort,
)
from xtm_oaev_sdk import BaseClient, Configuration, PingAlive, logger

__all__ = [
    "ListenQueue",
    "OpenAEVConfigHelper",
    "OpenAEVInjectorHelper",
    "create_mq_ssl_context",
]

_config: ConfigLookupPort = ConfigLookup()
_registration: InjectorRegistrationPort = InjectorRegistration()
_mq_ssl: MqSslPort = MqSsl()
_consumer: QueueConsumerPort = QueueConsumer(_mq_ssl)


def create_mq_ssl_context(config) -> ssl.SSLContext:
    """SSL context of the injector's RabbitMQ connection, from the ``mq``
    configuration (CA, client certificate and key, passphrase, verification)."""
    return _mq_ssl.create_mq_ssl_context(config)


class ListenQueue(threading.Thread):
    """RabbitMQ listener delivering inject messages to an injector callback."""

    def __init__(
        self,
        config: Dict,
        injector_config,
        logger,
        callback,
    ) -> None:
        threading.Thread.__init__(self)
        self.pika_credentials = None
        self.pika_parameters = None
        self.pika_connection = None
        self.channel = None

        self.callback = callback
        self.config = config
        self.logger = logger
        self.host = injector_config.connection["host"]
        self.vhost = injector_config.connection["vhost"]
        self.use_ssl = injector_config.connection["use_ssl"]
        self.port = injector_config.connection["port"]
        self.user = injector_config.connection["user"]
        self.password = injector_config.connection["pass"]
        self.queue_name = injector_config.listen
        self.exit_event = threading.Event()
        self.thread = None

    def _process_message(self, channel, method, properties, body) -> None:
        """process a message from the rabbit queue

        :param channel: channel instance
        :type channel: callable
        :param method: message methods
        :type method: callable
        :param properties: unused
        :type properties: str
        :param body: message body (data)
        :type body: str or bytes or bytearray
        """
        _consumer.process_message(self, channel, method, properties, body)

    def _data_handler(self, json_data) -> None:
        _consumer.handle_data(self, json_data)

    def run(self) -> None:
        _consumer.run(self)

    def stop(self):
        _consumer.stop(self)


class OpenAEVConfigHelper:
    """Legacy configuration accessor: hints, ``config.yml`` next to the injector,
    and tolerant lookups with defaults."""

    def __init__(self, base_path, variables: Dict | None, config_obj: Configuration):
        self.__config_obj = _config.load(base_path, variables, config_obj)

    @staticmethod
    def from_configuration_object(config: Configuration):
        return OpenAEVConfigHelper(None, None, config)

    def get_config_obj(self) -> Configuration:
        return self.__config_obj

    def get_conf(self, variable, is_number=None, default=None, required=None):
        return _config.get_conf(
            self.__config_obj, variable, is_number, default, required
        )

    def to_configuration(self):
        return self.__config_obj


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
        self.config = _registration.injector_config(config)

        self.logger_class = logger(*_registration.logger_settings(config))
        self.injector_logger = self.logger_class(config.get_conf("injector_name"))

        injector_icon = _registration.icon(config, icon)
        self.injector_config = _registration.register(
            self.api, self.config, injector_icon
        )
        self.connect_run_and_terminate = False
        self.scheduler = _registration.scheduler()
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
        return _registration.default_api_client()
