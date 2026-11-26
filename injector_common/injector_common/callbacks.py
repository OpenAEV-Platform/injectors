"""Bounded retry of the callbacks that carry a scan's results.

A scan may run for many minutes; losing its terminal callback or a target trace to
a transient network error (connection reset, platform restarting behind its proxy)
throws the whole result away. Those calls are retried a bounded number of times on
errors where the platform did not process the request: a connection error, a
timeout, or a gateway answer (502, 503, 504). Any other error, a 404 (inject
deleted) included, is raised at once, unchanged.
"""

import time
from typing import Any, Callable, Optional, Sequence

import requests

# Waits between attempts, in seconds: len(RETRY_DELAYS) + 1 attempts in total.
RETRY_DELAYS: Sequence[float] = (2, 5, 10)
# Gateway answers: the request did not reach the platform's handler.
RETRYABLE_STATUSES = frozenset({502, 503, 504})


def is_transient(error: BaseException) -> bool:
    """Whether ``error`` (or an error it was raised from) means the platform did
    not process the request, so sending it again is safe."""
    seen: set = set()
    current: Optional[BaseException] = error
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(
            current, (requests.exceptions.ConnectionError, requests.exceptions.Timeout)
        ):
            return True
        if getattr(current, "response_code", None) in RETRYABLE_STATUSES:
            return True
        current = current.__cause__ or current.__context__
    return False


def call_with_retry(
    call: Callable[[], Any],
    logger: Any,
    what: str,
    delays: Optional[Sequence[float]] = None,
) -> Any:
    """Run ``call``; on a transient error wait and try again, at most
    ``len(delays)`` more times, then raise the last error. ``what`` names the call
    in the log lines."""
    waits = list(RETRY_DELAYS if delays is None else delays)
    attempt = 0
    while True:
        try:
            return call()
        except Exception as err:  # noqa: BLE001
            if attempt >= len(waits) or not is_transient(err):
                raise
            delay = waits[attempt]
            attempt += 1
            logger.warning(
                f"{what} failed ({err}); retry {attempt}/{len(waits)} in {delay}s"
            )
            time.sleep(delay)
