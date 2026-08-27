"""Canonical synchronous Prowler client API."""

from .client import (
    DEFAULT_MAXIMUM_ACCEPTED_OUTPUT_BYTES,
    DEFAULT_TIMEOUT_SECONDS,
    ProwlerClient,
)
from .factory import ProwlerClientFactory

__all__ = [
    "DEFAULT_MAXIMUM_ACCEPTED_OUTPUT_BYTES",
    "DEFAULT_TIMEOUT_SECONDS",
    "ProwlerClient",
    "ProwlerClientFactory",
]
