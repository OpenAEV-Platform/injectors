"""injectors_second_sdk — OpenAEV Injectors SDK (DDD + Light Hex)."""

__version__ = "0.1.0"

from xtm_oaev_sdk import DaemonProtocol

from injectors_second_sdk.public import *  # noqa: F401, F403
from injectors_second_sdk.public import __all__ as _public_all

__all__ = _public_all
