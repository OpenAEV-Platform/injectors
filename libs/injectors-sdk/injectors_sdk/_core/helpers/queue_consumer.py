"""Queue consumer: deliver the injector's RabbitMQ messages to its callback."""

import json
import threading
import time
import traceback
from typing import Any

import pika
from injectors_sdk._core.helpers.mq_ssl import MqSsl
from injectors_sdk.seam.helpers import MqSslPort, QueueListenerProtocol

__all__ = ["QueueConsumer"]


class QueueConsumer:
    """Implements ``QueueConsumerPort``."""

    def __init__(self, mq_ssl: MqSslPort | None = None) -> None:
        self._mq_ssl = mq_ssl or MqSsl()

    def run(self, listener: QueueListenerProtocol) -> None:
        listener.logger.info("Starting ListenQueue thread")
        while not listener.exit_event.is_set():
            try:
                listener.logger.info("ListenQueue connecting to RabbitMQ.")
                # Connect the broker
                listener.pika_credentials = pika.PlainCredentials(
                    listener.user, listener.password
                )
                listener.pika_parameters = pika.ConnectionParameters(
                    host=listener.host,
                    port=listener.port,
                    virtual_host=listener.vhost,
                    credentials=listener.pika_credentials,
                    ssl_options=(
                        pika.SSLOptions(
                            self._mq_ssl.create_mq_ssl_context(listener.config),
                            listener.host,
                        )
                        if listener.use_ssl
                        else None
                    ),
                )
                listener.pika_connection = pika.BlockingConnection(
                    listener.pika_parameters
                )
                listener.channel = listener.pika_connection.channel()
                try:
                    # confirm_delivery is only for cluster mode rabbitMQ
                    # when not in cluster mode this line raise an exception
                    listener.channel.confirm_delivery()
                except Exception as err:  # pylint: disable=broad-except
                    listener.logger.error(str(err))
                listener.channel.basic_qos(prefetch_count=1)
                assert listener.channel is not None
                listener.channel.basic_consume(
                    queue=listener.queue_name,
                    on_message_callback=listener._process_message,
                )
                listener.channel.start_consuming()
            except Exception:  # pylint: disable=broad-except
                try:
                    listener.pika_connection.close()
                except Exception as errInException:
                    listener.logger.error(str(errInException))
                traceback.print_exc()
                # Wait some time and then retry ListenQueue again.
                time.sleep(10)

    def process_message(
        self,
        listener: QueueListenerProtocol,
        channel: Any,
        method: Any,
        properties: Any,
        body: Any,
    ) -> None:
        json_data = json.loads(body)
        # Message should be ack before processing as we don't own the processing
        # Not ACK the message here may lead to infinite re-deliver if the connector is broken
        # Also ACK, will not have any impact on the blocking aspect of the following functions
        channel.basic_ack(delivery_tag=method.delivery_tag)
        listener.thread = threading.Thread(
            target=listener._data_handler, args=[json_data]
        )
        listener.thread.start()

    def handle_data(self, listener: QueueListenerProtocol, json_data: Any) -> None:
        listener.callback(json_data)

    def stop(self, listener: QueueListenerProtocol) -> None:
        listener.logger.info("Preparing ListenQueue for clean shutdown")
        listener.exit_event.set()
        listener.pika_connection.close()
        if listener.thread:
            listener.thread.join()
