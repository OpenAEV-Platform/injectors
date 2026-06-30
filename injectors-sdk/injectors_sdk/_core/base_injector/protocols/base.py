"""BaseInjector lifecycle Protocol."""

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class BaseInjector(Protocol):
    """Lifecycle contract for injector extensions."""

    def process_message(self, data: dict[str, Any]) -> None: ...
    def start(self) -> None: ...
    def stop(self) -> None: ...
