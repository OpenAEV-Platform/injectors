import time
from typing import Dict, Optional

from pyoaev.helpers import OpenAEVInjectorHelper


def send_per_target_traces(
    helper: OpenAEVInjectorHelper,
    inject_id: str,
    ip_to_asset_id_map: Optional[Dict[str, str]],
    *,
    label: str,
    start: float,
    status: str = "INFO",
) -> None:
    """Emit one target-scoped execution trace per asset-backed target.

    Batch network injectors (nmap, nuclei, netexec) run a single command over all
    targets and only send a global aggregated callback, so each endpoint's result
    view shows "No traces on this target". This emits an intermediate
    ``command_execution`` trace per target carrying the target's asset id via
    ``execution_context_identifiers`` so the platform lists it under that target's
    execution timeline.

    Manual/inline targets have no asset id (they are absent from
    ``ip_to_asset_id_map``) and are therefore skipped - their output already
    appears in the global completion trace. The ``command_execution`` action keeps
    these traces intermediate so they never trigger the terminal-completion
    handling reserved for the final aggregated ``complete`` callback, which the
    caller still sends globally.
    """
    if not ip_to_asset_id_map:
        return
    logger = helper.injector_logger
    duration = int(time.time() - start)
    for target, asset_id in ip_to_asset_id_map.items():
        if not asset_id:
            continue
        try:
            helper.api.inject.execution_callback(
                inject_id=inject_id,
                data={
                    "execution_message": f"{label} executed against target {target}",
                    "execution_status": status,
                    "execution_duration": duration,
                    "execution_action": "command_execution",
                    "execution_context_identifiers": [asset_id],
                },
            )
            logger.info(
                f"Per-target execution trace sent for inject {inject_id} "
                f"(target '{target}', asset {asset_id})"
            )
        except Exception as exc:  # noqa: BLE001
            logger.error(
                f"Failed to send per-target execution trace for inject {inject_id} "
                f"(target '{target}', asset {asset_id}): {exc}"
            )
