"""Tests for the RabbitMQ ListenQueue and its SSL context."""

import json
from unittest.mock import MagicMock, patch

from injectors_sdk import ListenQueue, create_mq_ssl_context

CONNECTION = {
    "host": "rabbit",
    "vhost": "/",
    "use_ssl": False,
    "port": 5672,
    "user": "guest",
    "pass": "secret",
}


def _given_queue(callback=None) -> ListenQueue:
    injector_config = MagicMock(connection=CONNECTION, listen="injector-queue")
    return ListenQueue({}, injector_config, MagicMock(), callback or MagicMock())


def test_reads_the_broker_connection_from_the_injector_config() -> None:
    """It takes host, credentials and queue from the registration answer."""
    queue = _given_queue()
    assert (queue.host, queue.port, queue.user, queue.password) == (
        "rabbit",
        5672,
        "guest",
        "secret",
    )
    assert queue.queue_name == "injector-queue"


def test_process_message_acks_then_hands_json_to_the_callback() -> None:
    """It acknowledges first, then processes the decoded message."""
    callback = MagicMock()
    queue = _given_queue(callback)
    channel = MagicMock()

    queue._process_message(channel, MagicMock(delivery_tag=7), None, b'{"a": 1}')
    queue.thread.join()

    channel.basic_ack.assert_called_once_with(delivery_tag=7)
    callback.assert_called_once_with(json.loads('{"a": 1}'))


@patch("injectors_sdk._core.helpers.mq_ssl.ssl")
def test_ssl_context_is_unverified_unless_rejection_is_enabled(mock_ssl) -> None:
    """It mirrors MQ_USE_SSL_REJECT_UNAUTHORIZED (default: unverified)."""
    create_mq_ssl_context({})
    mock_ssl._create_unverified_context.assert_called_once()

    mock_ssl.reset_mock()
    create_mq_ssl_context({"mq": {"use_ssl_reject_unauthorized": True}})
    mock_ssl._create_unverified_context.assert_not_called()
