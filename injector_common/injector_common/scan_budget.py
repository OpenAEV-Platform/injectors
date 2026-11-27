"""Whole-scan time budget of a scanning injector.

A scan that runs past the platform inject execution threshold is finalized by the
platform as timed out, and the results the injector sends afterwards no longer
change the inject's status. A scanning injector therefore bounds its whole run by a
time budget kept below that threshold, and reports what it scanned before the
budget ran out instead of losing everything.

The limit in force and where it came from (inject field, deployment variable,
platform threshold, platform cap, fallback) are stated on the inject at scan start,
so an operator can tell which limit governed a run, cut or not.

Shared by the Nuclei and Nmap injectors.
"""

import time
from typing import NamedTuple, Optional, Tuple

from injector_common.inject_gone import InjectGoneError, is_inject_gone

# Inject field holding the per-inject whole-scan ceiling, in seconds.
SCAN_TIMEOUT_FIELD = "scan_timeout_seconds"
# Ceiling used when neither the inject, the deployment nor the platform gives one.
DEFAULT_SCAN_TIMEOUT = 540
# Margin kept below the platform inject execution threshold: past the threshold
# the platform finalizes the inject itself and refuses the injector's results.
THRESHOLD_MARGIN_SECONDS = 60
# Runtime setting of OpenAEV (GET /api/settings, runtime_settings).
THRESHOLD_SETTING_KEY = "inject_execution_threshold_minutes"
# Platform route of the settings. Never tenant-scoped: pyoaev prefixes a relative
# path with /api/tenants/<id>/ when OPENAEV_TENANT_ID is set, a route the platform
# does not serve for its settings, so the threshold is read on the full URL.
SETTINGS_ROUTE = "/api/settings"
# A threshold read is reused this long (seconds): an administrator may change the
# setting at runtime, a scan burst must not read it once per inject.
THRESHOLD_CACHE_SECONDS = 300

# Where the limit of a scan came from (the "source" of ScanTimeLimit).
SOURCE_INJECT = "inject field " + SCAN_TIMEOUT_FIELD
SOURCE_DEPLOYMENT = "deployment variable {variable}"
SOURCE_THRESHOLD = (
    "platform inject execution threshold ({minutes} min) minus {margin} s"
)
SOURCE_CAP = (
    "platform cap: {requested} s from the {origin} capped below the platform inject "
    "execution threshold ({minutes} min)"
)
SOURCE_FALLBACK = "fallback, the platform inject execution threshold is unreadable"

# Attributes kept on the helper's API client: the threshold cache and whether the
# unreadable threshold was already logged at ERROR.
_CACHE_ATTRIBUTE = "_scan_budget_threshold"
_READ_FAILED = "the settings read failed"
_FALLBACK_LOGGED_ATTRIBUTE = "_scan_budget_fallback_logged"


class ScanTimeLimit(NamedTuple):
    """The whole-scan ceiling of one inject and where it came from."""

    seconds: int
    source: str
    fallback: bool = False
    # Why the platform threshold could not be read, when it could not.
    threshold_error: Optional[str] = None


def positive_int(value) -> Optional[int]:
    """A strictly positive integer out of an inject or setting value, else None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, list):
        value = value[0] if value else None
    if isinstance(value, int):
        return value if value > 0 else None
    if isinstance(value, str) and value.strip().isdigit():
        number = int(value.strip())
        return number if number > 0 else None
    return None


def _settings_url(api) -> str:
    """The platform settings URL, outside any tenant prefix. A full URL is passed
    through unchanged by pyoaev, with the client's session, token and TLS options."""
    base = getattr(api, "url", None)
    if isinstance(base, str) and base.strip():
        return base.strip().rstrip("/") + SETTINGS_ROUTE
    return "/settings"


def _read_threshold(helper) -> Tuple[Optional[int], Optional[str]]:
    """(threshold seconds, None) or (None, why it could not be read). Cached on the
    API client for THRESHOLD_CACHE_SECONDS when the read succeeded."""
    api = helper.api
    cached = vars(api).get(_CACHE_ATTRIBUTE) if hasattr(api, "__dict__") else None
    now = time.monotonic()
    if cached and now - cached[0] < THRESHOLD_CACHE_SECONDS:
        return cached[1], None
    try:
        settings = api.http_get(_settings_url(api))
    except Exception as err:  # noqa: BLE001
        return None, f"{_READ_FAILED} ({err})"
    items = settings.get("runtime_settings") if isinstance(settings, dict) else None
    threshold = None
    for item in items if isinstance(items, list) else []:
        if isinstance(item, dict) and item.get("key") == THRESHOLD_SETTING_KEY:
            minutes = positive_int(item.get("value"))
            threshold = minutes * 60 if minutes else None
            break
    if threshold is None:
        return None, f"the platform settings carry no {THRESHOLD_SETTING_KEY}"
    try:
        setattr(api, _CACHE_ATTRIBUTE, (now, threshold))
    except Exception:  # noqa: BLE001
        pass
    return threshold, None


def platform_threshold_seconds(helper) -> Optional[int]:
    """The platform inject execution threshold in seconds, or None.

    Read from the runtime_settings of GET /api/settings on the platform route (never
    the tenant-scoped one), cached a few minutes. Best-effort: an older platform, a
    missing setting or a failed read answers None.
    """
    threshold, error = _read_threshold(helper)
    if error:
        helper.injector_logger.warning(
            "Could not read the platform inject execution threshold: " + error
        )
    return threshold


def _log_fallback(helper, limit: ScanTimeLimit, deployment_variable: str) -> None:
    """The fallback at ERROR once per client (visible at INJECTOR_LOG_LEVEL=error),
    at WARNING after that."""
    api = helper.api
    message = (
        f"Scan time limit {limit.seconds} s ({limit.source}: "
        f"{limit.threshold_error}). Raise it with the inject field "
        f"'{SCAN_TIMEOUT_FIELD}' or the {deployment_variable} key of the injector "
        "deployment."
    )
    logged = (
        vars(api).get(_FALLBACK_LOGGED_ATTRIBUTE) if hasattr(api, "__dict__") else None
    )
    if logged:
        helper.injector_logger.warning(message)
        return
    helper.injector_logger.error(message)
    try:
        setattr(api, _FALLBACK_LOGGED_ATTRIBUTE, True)
    except Exception:  # noqa: BLE001
        pass


def resolve_scan_timeout(
    helper,
    inject_content,
    deployment_value,
    deployment_variable: str = "scan time limit",
) -> ScanTimeLimit:
    """The whole-scan ceiling of one inject, in seconds, and its source.

    The inject field scan_timeout_seconds, else the deployment value, else the
    platform inject execution threshold minus a margin, else 540 s. Capped below
    the platform threshold when it is known: past it the platform finalizes the
    inject itself and the scan results are refused.
    """
    requested = None
    origin = None
    if isinstance(inject_content, dict):
        requested = positive_int(inject_content.get(SCAN_TIMEOUT_FIELD))
        origin = SOURCE_INJECT if requested is not None else None
    if requested is None:
        requested = positive_int(deployment_value)
        if requested is not None:
            origin = SOURCE_DEPLOYMENT.format(variable=deployment_variable)
    threshold, threshold_error = _read_threshold(helper)
    if threshold_error and threshold_error.startswith(_READ_FAILED):
        helper.injector_logger.warning(
            "Could not read the platform inject execution threshold: " + threshold_error
        )
    ceiling = (
        max(threshold - THRESHOLD_MARGIN_SECONDS, THRESHOLD_MARGIN_SECONDS)
        if threshold
        else None
    )
    if requested is None:
        if ceiling:
            return ScanTimeLimit(
                ceiling,
                SOURCE_THRESHOLD.format(
                    minutes=threshold // 60, margin=THRESHOLD_MARGIN_SECONDS
                ),
            )
        limit = ScanTimeLimit(
            DEFAULT_SCAN_TIMEOUT, SOURCE_FALLBACK, True, threshold_error
        )
        _log_fallback(helper, limit, deployment_variable)
        return limit
    if ceiling and requested > ceiling:
        helper.injector_logger.warning(
            f"Scan time limit {requested}s capped to {ceiling}s, below the "
            f"platform inject execution threshold ({threshold}s)."
        )
        return ScanTimeLimit(
            ceiling,
            SOURCE_CAP.format(
                requested=requested, origin=origin, minutes=threshold // 60
            ),
        )
    return ScanTimeLimit(requested, origin)


def scan_time_limit_message(limit: ScanTimeLimit, deployment_variable: str) -> str:
    """The scan-start trace text: the limit and its source; on the fallback, a
    warning naming the two ways to raise it."""
    text = f"scan time limit: {limit.seconds} s (source: {limit.source})"
    if not limit.fallback:
        return text
    return (
        f"Warning: {text}: {limit.threshold_error or 'unknown reason'}. The scan is "
        f"cut at {limit.seconds} s whatever the platform threshold: raise it with "
        f"the inject field '{SCAN_TIMEOUT_FIELD}' or the {deployment_variable} key "
        "of the injector deployment."
    )


def send_scan_time_limit_trace(
    helper,
    inject_id: str,
    limit: ScanTimeLimit,
    deployment_variable: str,
    start: float,
) -> None:
    """One INFO ``command_execution`` trace at scan start stating the limit in force
    and its source. A 404 means the inject was deleted: InjectGoneError, so the
    caller aborts before the run; any other failure is logged."""
    try:
        helper.api.inject.execution_callback(
            inject_id=inject_id,
            data={
                "execution_message": scan_time_limit_message(
                    limit, deployment_variable
                ),
                "execution_status": "INFO",
                "execution_duration": int(time.time() - start),
                "execution_action": "command_execution",
            },
        )
    except Exception as exc:  # noqa: BLE001
        if is_inject_gone(exc):
            raise InjectGoneError(inject_id, exc) from exc
        helper.injector_logger.error(
            f"Failed to send the scan time limit trace for inject {inject_id}: {exc}"
        )
