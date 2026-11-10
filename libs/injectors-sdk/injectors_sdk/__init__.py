"""injectors-sdk — OpenAEV Injectors SDK (DDD + Light Hex Architecture).

Built on the shared ``xtm-oaev-sdk``; never depends on the pyoaev client.

Architecture:
    _core/helpers/   Configuration lookup, registration, queue consumption, MQ SSL
    seam/helpers/    Injector runtime ports (closed, versioned)
    public/helpers   Injector helper adapters
    public/          User-facing re-exports

Port/adapter layering: ``seam`` holds the contracts and imports nothing from
``_core`` nor ``public``; ``_core`` implements the seam ports and never imports
``public``; ``public`` exposes adapters that speak seam types and delegate to
``_core`` — never a core object.

The OpenAEV API client is injected (``api_client=``), conforming to
``xtm_oaev_sdk.BaseClient``.
"""

__version__ = "0.1.0"

from injectors_sdk.public import *  # noqa: F401, F403
from injectors_sdk.public import __all__ as _public_all

__all__ = list(_public_all)
