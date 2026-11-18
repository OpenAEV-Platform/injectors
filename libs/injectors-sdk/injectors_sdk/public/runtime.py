"""Injector runtime adapters: the dev options and dev help of an injector.

Each adapter speaks the runtime seam types and delegates to the core implementation of
its port.
"""

from injectors_sdk._core.runtime import InjectorDevRuntime
from injectors_sdk.seam.runtime import InjectorDevOptions, InjectorDevRuntimePort

__all__ = ["InjectorDevOptions", "injector_dev_help", "injector_dev_options"]

_dev: InjectorDevRuntimePort = InjectorDevRuntime()


def injector_dev_options(argv: list[str] | None = None) -> InjectorDevOptions:
    """Reads the dev options of an injector: the common ones plus its own.

    :param argv: the arguments to read, the process arguments when omitted.
    :return: the options, frozen. Options are read only under their full name;
        collector options and the injector's own flags are left alone.
    """
    return _dev.options(argv)


def injector_dev_help() -> str:
    """Returns the help of the injector dev options."""
    return _dev.help()
