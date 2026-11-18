"""Injector runtime ports: the behaviour the public runtime expects from the core."""

from typing import Any, Callable, Protocol, runtime_checkable

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

    def api_client(self, config: Any, options: InjectorDevOptions) -> Any:
        """A stand-in of the platform client: it offers the managers an injector
        calls, writes each call to the dev sink, and raises ``NeedsPlatformError`` for
        any call only the platform can answer. Secrets from the configuration and the
        environment are redacted from what it writes."""

    def run(
        self,
        api: Any,
        injector_config: dict[str, Any],
        callback: Callable[[dict[str, Any]], None],
        logger: Any,
        options: InjectorDevOptions,
    ) -> int:
        """Run ``callback`` on the ``--inject`` message, as the platform publishes it,
        completed and checked like the platform does, then wait for the inject's
        ``complete`` callback. Return the exit code: 0 completed, 1 failed or not
        completed within ``options.timeout``, 2 refused before running."""
