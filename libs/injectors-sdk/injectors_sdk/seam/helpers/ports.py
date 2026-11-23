"""Injector helpers ports: the behaviour the public helpers expect from the core."""

import sched
import ssl
import threading
from typing import Any, Callable, Protocol, runtime_checkable

from xtm_oaev_sdk import BaseClient, ConfigurationProtocol

__all__ = [
    "ConfigLookupPort",
    "InjectorRegistrationPort",
    "MqSslPort",
    "QueueConsumerPort",
    "QueueListenerProtocol",
]


@runtime_checkable
class ConfigLookupPort(Protocol):
    """Legacy configuration access of injectors."""

    def load(
        self, base_path: Any, variables: dict | None, config_obj: Any
    ) -> ConfigurationProtocol:
        """The given configuration, or one built from the hints and the
        ``config.yml`` next to ``base_path``."""

    def get_conf(
        self,
        configuration: ConfigurationProtocol,
        variable: Any,
        is_number: Any = None,
        default: Any = None,
        required: Any = None,
    ) -> Any:
        """Configured value, else ``default``; ValueError when a required key
        has neither."""


@runtime_checkable
class InjectorRegistrationPort(Protocol):
    """Registers an injector on the platform."""

    def injector_config(self, config: Any) -> dict[str, Any]:
        """Registration payload of the injector."""

    def logger_settings(self, config: Any) -> tuple[Any, Any]:
        """Log level and JSON logging flag of the injector."""

    def icon(self, config: Any, icon: Any) -> tuple[str, Any, str]:
        """Icon upload tuple of the injector."""

    def register(
        self, api: Any, injector_config: dict[str, Any], injector_icon: Any
    ) -> Any:
        """Create the injector; the platform answer (queue connection) is returned."""

    def scheduler(self) -> sched.scheduler:
        """Scheduler available to the injector."""

    def default_api_client(self) -> BaseClient:
        """The API client used when none is injected: none, the SDK refuses."""


@runtime_checkable
class QueueListenerProtocol(Protocol):
    """State of a queue listener, read and updated by the queue consumer."""

    callback: Callable[[Any], Any]
    config: Any
    logger: Any
    host: Any
    vhost: Any
    use_ssl: Any
    port: Any
    user: Any
    password: Any
    queue_name: Any
    exit_event: threading.Event
    thread: threading.Thread | None
    pika_credentials: Any
    pika_parameters: Any
    pika_connection: Any
    channel: Any

    def _process_message(self, channel, method, properties, body) -> None:
        """Process one queue message."""

    def _data_handler(self, json_data) -> None:
        """Hand a decoded message to the callback."""


@runtime_checkable
class QueueConsumerPort(Protocol):
    """Consumes the injector's RabbitMQ queue."""

    def run(self, listener: QueueListenerProtocol) -> None:
        """Connect and consume until stopped, reconnecting after failures."""

    def process_message(
        self,
        listener: QueueListenerProtocol,
        channel: Any,
        method: Any,
        properties: Any,
        body: Any,
    ) -> None:
        """Acknowledge a message, then handle it in its own thread."""

    def handle_data(self, listener: QueueListenerProtocol, json_data: Any) -> None:
        """Hand a decoded message to the listener's callback."""

    def stop(self, listener: QueueListenerProtocol) -> None:
        """Stop consuming and wait for the message being handled."""


@runtime_checkable
class MqSslPort(Protocol):
    """Builds the SSL context of the RabbitMQ connection."""

    def create_mq_ssl_context(self, config: Any) -> ssl.SSLContext:
        """SSL context from the ``mq`` configuration."""
