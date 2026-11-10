"""Injector helpers seam: the contract between the public helpers and the core.

Closed: it imports nothing from ``injectors_sdk._core`` nor
``injectors_sdk.public``. Any change to these contracts must bump
:data:`SEAM_VERSION`.
"""

from injectors_sdk.seam.helpers.ports import (
    ConfigLookupPort,
    InjectorRegistrationPort,
    MqSslPort,
    QueueConsumerPort,
    QueueListenerProtocol,
)

#: Version of the injector helpers seam. Bump on any contract change.
SEAM_VERSION = "1.0.0"

__all__ = [
    "SEAM_VERSION",
    "ConfigLookupPort",
    "InjectorRegistrationPort",
    "MqSslPort",
    "QueueConsumerPort",
    "QueueListenerProtocol",
]
