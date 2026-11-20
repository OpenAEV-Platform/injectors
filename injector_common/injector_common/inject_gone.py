"""Recognise an inject deleted on the platform while an injector handles it.

Once an inject is deleted, every inject endpoint of the platform answers HTTP
404 (pyoaev raises an ``OpenAEVError`` subclass carrying ``response_code``
404, possibly wrapped by another error such as ``SignatureTransmissionError``).
Nothing is left to report to: the injector must stop its work, never launch
the tool against live hosts, and log one line instead of a stream of errors
or an unhandled traceback.
"""

from contextlib import contextmanager
from typing import Any, Iterator, Optional

INJECT_GONE_STATUS = 404


class InjectGoneError(Exception):
    """The inject no longer exists on the platform (HTTP 404 on a callback)."""

    def __init__(self, inject_id: str, cause: Optional[BaseException] = None):
        super().__init__(f"inject {inject_id} no longer exists on the platform")
        self.inject_id = inject_id
        self.cause = cause


def is_inject_gone(error: Optional[BaseException]) -> bool:
    """Tell whether ``error`` (or an error it was raised from) is a 404.

    The cause chain is walked because pyoaev re-raises HTTP errors under
    other types (``on_http_error``, signature transmission) with ``from``.
    """
    seen: set = set()
    current = error
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, InjectGoneError):
            return True
        if getattr(current, "response_code", None) == INJECT_GONE_STATUS:
            return True
        current = current.__cause__ or current.__context__
    return False


def log_inject_gone(logger: Any, inject_id: Optional[str]) -> None:
    """Log the single line an injector writes when it aborts on a deleted inject."""
    logger.warning(f"inject {inject_id} deleted, aborting")


def inject_id_from_payload(data: Any) -> Optional[str]:
    """Read the inject id of a queue message without ever raising."""
    injection = data.get("injection") if isinstance(data, dict) else None
    return injection.get("inject_id") if isinstance(injection, dict) else None


@contextmanager
def abort_on_inject_gone(logger: Any, data: Any) -> Iterator[None]:
    """Wrap the handling of one queue message.

    An error that means the inject was deleted (a 404 on any callback,
    reception, per-target trace, final callback or signatures) ends the
    handling with one log line instead of an unhandled traceback in the
    per-message thread. Every other error propagates unchanged.
    """
    try:
        yield
    except Exception as err:  # noqa: BLE001
        if not is_inject_gone(err):
            raise
        inject_id = getattr(err, "inject_id", None) or inject_id_from_payload(data)
        log_inject_gone(logger, inject_id)
