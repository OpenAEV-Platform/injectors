"""Injector runtime ports: the behaviour the public runtime expects from the core."""

from typing import Protocol, runtime_checkable

from injectors_sdk.seam.runtime.models import InjectorDevOptions

__all__ = ["InjectorDevRuntimePort"]


@runtime_checkable
class InjectorDevRuntimePort(Protocol):
    """Runs an injector without the platform (dev mode)."""

    def options(self, argv: list[str] | None = None) -> InjectorDevOptions:
        """The injector's dev options, read from ``argv`` (the process arguments when
        ``None``). Options are read only under their full name; collector options and
        the injector's own flags are left alone."""

    def help(self) -> str:
        """Help of the injector's dev options: the common ones and its own."""

    def exit_on_help(self, options: InjectorDevOptions) -> None:
        """Print the dev help and exit with code 0 when ``options`` ask for it."""
