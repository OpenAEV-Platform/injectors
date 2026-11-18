"""Injector runtime seam: the contract between the public runtime and the core.

Closed: it imports nothing from ``injectors_sdk._core`` nor ``injectors_sdk.public``.
Any change to these contracts must bump :data:`SEAM_VERSION`.
"""

from injectors_sdk.seam.runtime.models import InjectorDevOptions
from injectors_sdk.seam.runtime.ports import InjectorDevRuntimePort

#: Version of the injector runtime seam. Bump on any contract change.
SEAM_VERSION = "1.0.0"

__all__ = ["SEAM_VERSION", "InjectorDevOptions", "InjectorDevRuntimePort"]
