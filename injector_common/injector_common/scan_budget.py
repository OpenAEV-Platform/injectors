"""Whole-scan time budget of a scanning injector.

A scan that runs past the platform inject execution threshold is finalized by the
platform as timed out, and the results the injector sends afterwards no longer
change the inject's status. A scanning injector therefore bounds its whole run by a
time budget kept below that threshold, and reports what it scanned before the
budget ran out instead of losing everything.

Shared by the Nuclei and Nmap injectors.
"""

from typing import Optional

# Inject field holding the per-inject whole-scan ceiling, in seconds.
SCAN_TIMEOUT_FIELD = "scan_timeout_seconds"
# Ceiling used when neither the inject, the deployment nor the platform gives one.
DEFAULT_SCAN_TIMEOUT = 540
# Margin kept below the platform inject execution threshold: past the threshold
# the platform finalizes the inject itself and refuses the injector's results.
THRESHOLD_MARGIN_SECONDS = 60
# Runtime setting of OpenAEV (GET /api/settings, runtime_settings).
THRESHOLD_SETTING_KEY = "inject_execution_threshold_minutes"


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


def platform_threshold_seconds(helper) -> Optional[int]:
    """The platform inject execution threshold in seconds, or None.

    Read per inject (an administrator changes it at runtime) from the
    runtime_settings of GET /api/settings. Best-effort: an older platform,
    a missing setting or a failed read answers None.
    """
    try:
        settings = helper.api.http_get("/settings")
    except Exception as err:
        helper.injector_logger.warning(
            "Could not read the platform inject execution threshold: " + str(err)
        )
        return None
    items = settings.get("runtime_settings") if isinstance(settings, dict) else None
    for item in items if isinstance(items, list) else []:
        if isinstance(item, dict) and item.get("key") == THRESHOLD_SETTING_KEY:
            minutes = positive_int(item.get("value"))
            return minutes * 60 if minutes else None
    return None


def resolve_scan_timeout(helper, inject_content, deployment_value) -> int:
    """The whole-scan ceiling of one inject, in seconds.

    The inject field scan_timeout_seconds, else the deployment value, else the
    platform inject execution threshold minus a margin, else 540 s. Capped below
    the platform threshold when it is known: past it the platform finalizes the
    inject itself and the scan results are refused.
    """
    requested = None
    if isinstance(inject_content, dict):
        requested = positive_int(inject_content.get(SCAN_TIMEOUT_FIELD))
    if requested is None:
        requested = positive_int(deployment_value)
    threshold = platform_threshold_seconds(helper)
    ceiling = (
        max(threshold - THRESHOLD_MARGIN_SECONDS, THRESHOLD_MARGIN_SECONDS)
        if threshold
        else None
    )
    if requested is None:
        return ceiling or DEFAULT_SCAN_TIMEOUT
    if ceiling and requested > ceiling:
        helper.injector_logger.warning(
            f"Scan time limit {requested}s capped to {ceiling}s, below the "
            f"platform inject execution threshold ({threshold}s)."
        )
        return ceiling
    return requested
