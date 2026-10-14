"""RabbitMQ listener delivering inject messages to an injector callback."""

import json
import ssl
import threading
import time
import traceback
from typing import Dict

import pika
from xtm_oaev_sdk import Configuration, ssl_cert_chain, ssl_verify_locations

__all__ = ["ListenQueue", "create_mq_ssl_context"]


def create_mq_ssl_context(config) -> ssl.SSLContext:
    config_obj = Configuration(
        config_hints={
            "MQ_USE_SSL_CA": {
                "env": "MQ_USE_SSL_CA",
                "file_path": ["mq", "use_ssl_ca"],
            },
            "MQ_USE_SSL_CERT": {
                "env": "MQ_USE_SSL_CERT",
                "file_path": ["mq", "use_ssl_cert"],
            },
            "MQ_USE_SSL_KEY": {
                "env": "MQ_USE_SSL_KEY",
                "file_path": ["mq", "use_ssl_key"],
            },
            "MQ_USE_SSL_REJECT_UNAUTHORIZED": {
                "env": "MQ_USE_SSL_REJECT_UNAUTHORIZED",
                "file_path": ["mq", "use_ssl_reject_unauthorized"],
                "is_number": False,
                "default": False,
            },
            "MQ_USE_SSL_PASSPHRASE": {
                "env": "MQ_USE_SSL_PASSPHRASE",
                "file_path": ["mq", "use_ssl_passphrase"],
            },
        },
        config_values=config,
    )
    use_ssl_ca = config_obj.get("MQ_USE_SSL_CA")
    use_ssl_cert = config_obj.get("MQ_USE_SSL_CERT")
    use_ssl_key = config_obj.get("MQ_USE_SSL_KEY")
    use_ssl_reject_unauthorized = config_obj.get("MQ_USE_SSL_REJECT_UNAUTHORIZED")
    use_ssl_passphrase = config_obj.get("MQ_USE_SSL_PASSPHRASE")
    ssl_context = ssl.create_default_context()
    # If no rejection allowed, use private function to generate unverified context
    if not use_ssl_reject_unauthorized:
        # noinspection PyUnresolvedReferences,PyProtectedMember
        ssl_context = ssl._create_unverified_context()
    ssl_verify_locations(ssl_context, use_ssl_ca)
    # Thanks to https://bugs.python.org/issue16487 is not possible today to easily use memory pem
    # in SSL context. We need to write it to a temporary file before
    ssl_cert_chain(ssl_context, use_ssl_cert, use_ssl_key, use_ssl_passphrase)
    return ssl_context


class ListenQueue(threading.Thread):
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

    # noinspection PyUnusedLocal
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
        json_data = json.loads(body)
        # Message should be ack before processing as we don't own the processing
        # Not ACK the message here may lead to infinite re-deliver if the connector is broken
        # Also ACK, will not have any impact on the blocking aspect of the following functions
        channel.basic_ack(delivery_tag=method.delivery_tag)
        self.thread = threading.Thread(target=self._data_handler, args=[json_data])
        self.thread.start()

    def _data_handler(self, json_data) -> None:
        self.callback(json_data)

    def run(self) -> None:
        self.logger.info("Starting ListenQueue thread")
        while not self.exit_event.is_set():
            try:
                self.logger.info("ListenQueue connecting to RabbitMQ.")
                # Connect the broker
                self.pika_credentials = pika.PlainCredentials(self.user, self.password)
                self.pika_parameters = pika.ConnectionParameters(
                    host=self.host,
                    port=self.port,
                    virtual_host=self.vhost,
                    credentials=self.pika_credentials,
                    ssl_options=(
                        pika.SSLOptions(create_mq_ssl_context(self.config), self.host)
                        if self.use_ssl
                        else None
                    ),
                )
                self.pika_connection = pika.BlockingConnection(self.pika_parameters)
                self.channel = self.pika_connection.channel()
                try:
                    # confirm_delivery is only for cluster mode rabbitMQ
                    # when not in cluster mode this line raise an exception
                    self.channel.confirm_delivery()
                except Exception as err:  # pylint: disable=broad-except
                    self.logger.error(str(err))
                self.channel.basic_qos(prefetch_count=1)
                assert self.channel is not None
                self.channel.basic_consume(
                    queue=self.queue_name, on_message_callback=self._process_message
                )
                self.channel.start_consuming()
            except Exception:  # pylint: disable=broad-except
                try:
                    self.pika_connection.close()
                except Exception as errInException:
                    self.logger.error(str(errInException))
                traceback.print_exc()
                # Wait some time and then retry ListenQueue again.
                time.sleep(10)

    def stop(self):
        self.logger.info("Preparing ListenQueue for clean shutdown")
        self.exit_event.set()
        self.pika_connection.close()
        if self.thread:
            self.thread.join()
