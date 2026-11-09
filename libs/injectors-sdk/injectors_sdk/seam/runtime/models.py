"""Injector runtime data contracts: the dev options of an injector."""

from dataclasses import dataclass

from xtm_oaev_sdk import DevOptions

__all__ = ["InjectorDevOptions"]


@dataclass(frozen=True)
class InjectorDevOptions(DevOptions):
    """Dev options of an injector: the common ones plus the injector's own.

    ``inject`` names the inject message to run (``-`` for stdin), ``timeout`` how many
    seconds to wait for it to complete, ``emit`` what the run
    also writes on stdout, in the order asked (``expectations``), ``dump_contracts`` and
    ``list_contracts`` ask for the injector's registration or contract list, and
    ``new_inject`` names the contract to write an inject message for.
    """

    inject: str | None = None
    timeout: float = 600.0
    emit: tuple[str, ...] = ()
    dump_contracts: bool = False
    list_contracts: bool = False
    new_inject: str | None = None
