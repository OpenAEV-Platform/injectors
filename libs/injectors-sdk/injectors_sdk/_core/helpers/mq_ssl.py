"""MQ SSL: the SSL context of the injector's RabbitMQ connection."""

import ssl
from typing import Any

from xtm_oaev_sdk import Configuration, ssl_cert_chain, ssl_verify_locations

__all__ = ["MqSsl"]


class MqSsl:
    """Implements ``MqSslPort``."""

    def create_mq_ssl_context(self, config: Any) -> ssl.SSLContext:
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
