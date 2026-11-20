"""Per-target outcomes of a batch network scan and the global status they imply.

Batch network injectors (nmap, nuclei, netexec) run one command over every target and
send one global ``complete`` callback. The helpers here let them report, after the run,
what happened to each target (one target-scoped trace per asset-backed target) and
derive a global status that reflects partial success instead of a binary SUCCESS/ERROR.

The tool-specific part (reading the tool's output into a ``TargetOutcome`` per target)
stays in each injector; nmap is the reference implementation.
"""

import time
from dataclasses import dataclass
from typing import Iterable, Optional

from pyoaev.helpers import OpenAEVInjectorHelper

from injector_common.inject_gone import InjectGoneError, is_inject_gone
from injector_common.targets import (
    NO_RESULT_REASON,
    MissedTarget,
    SkippedAsset,
    TargetResolution,
)

# Execution trace statuses understood by the platform (ExecutionTraceStatus).
# WARNING counts as a successful execution; INFO is not counted.
EXECUTED = "EXECUTED"
WARNING = "WARNING"
ERROR = "ERROR"
INFO = "INFO"

HOST_UP = "up"
HOST_DOWN = "down"
NOT_SCANNED = "not_scanned"

# One trace per target: keep each message short, an asset group can hold hundreds.
MAX_TRACE_MESSAGE_LENGTH = 300
# Lines listing the targets that were missed, in the global message.
MAX_LISTED_TARGETS = 50

THRESHOLD_SETTING = "inject.execution.threshold.minutes"


def _cap(message: str, limit: int = MAX_TRACE_MESSAGE_LENGTH) -> str:
    if len(message) <= limit:
        return message
    return message[: limit - 3] + "..."


@dataclass
class TargetOutcome:
    """What a scan returned for one target: host up (with its open ports), host down
    or no response, or not scanned at all (with the reason)."""

    resolution: TargetResolution
    state: str
    open_ports: int = 0
    reason: Optional[str] = None

    @classmethod
    def from_missed(cls, missed: MissedTarget) -> "TargetOutcome":
        return cls(missed.resolution, NOT_SCANNED, reason=missed.reason)

    @property
    def status(self) -> str:
        return EXECUTED if self.state == HOST_UP else WARNING

    @property
    def scanned(self) -> bool:
        return self.state != NOT_SCANNED

    def _subject(self) -> str:
        target = self.resolution.target
        label = self.resolution.asset_label()
        return f"{target} (asset {label})" if label else target

    def describe(self) -> str:
        """E.g. '10.0.0.2 (asset db-02): host up, 2 open ports'."""
        if self.state == HOST_UP:
            if self.open_ports == 1:
                detail = "host up, 1 open port"
            elif self.open_ports:
                detail = f"host up, {self.open_ports} open ports"
            else:
                detail = "host up, no open port"
        elif self.state == HOST_DOWN:
            detail = "host down or no response"
        else:
            detail = f"not scanned, {self.reason or NO_RESULT_REASON}"
        return _cap(f"{self._subject()}: {detail}")


@dataclass
class ScanSummary:
    total: int
    scanned: int
    up: int
    missed: int
    open_ports: int
    exit_code: int = 0
    tool: str = "the scan"

    @property
    def status(self) -> str:
        """EXECUTED when every target answered; WARNING (a success on the platform)
        when some were missed or the tool exited non-zero but its output was kept."""
        if self.missed or self.exit_code:
            return WARNING
        return EXECUTED

    def headline(self) -> str:
        text = (
            f"{self.scanned}/{self.total} targets scanned, {self.up} up, "
            f"{self.missed} missed, {self.open_ports} open ports"
        )
        if self.exit_code:
            text += f" ({self.tool} exited with code {self.exit_code}, results kept)"
        return text


def summarize_outcomes(
    outcomes: Iterable[TargetOutcome],
    open_ports: int,
    exit_code: int = 0,
    tool: str = "the scan",
) -> ScanSummary:
    """Counts of a run. ``open_ports`` is the number of open ports the tool found,
    hosts matching no target included, so it is passed by the caller."""
    outcomes = list(outcomes)
    up = sum(1 for o in outcomes if o.state == HOST_UP)
    scanned = sum(1 for o in outcomes if o.scanned)
    return ScanSummary(
        total=len(outcomes),
        scanned=scanned,
        up=up,
        missed=len(outcomes) - up,
        open_ports=open_ports,
        exit_code=exit_code,
        tool=tool,
    )


def build_global_message(
    summary: ScanSummary, outcomes: Iterable[TargetOutcome]
) -> str:
    """The headline with the counts, then one line per target that was missed."""
    missed = [o for o in outcomes if o.state != HOST_UP]
    lines = [summary.headline()]
    for outcome in missed[:MAX_LISTED_TARGETS]:
        lines.append(f"- {outcome.describe()}")
    if len(missed) > MAX_LISTED_TARGETS:
        lines.append(f"- and {len(missed) - MAX_LISTED_TARGETS} more")
    return "\n".join(lines)


def send_target_outcome_traces(
    helper: OpenAEVInjectorHelper,
    inject_id: str,
    outcomes: Optional[Iterable[TargetOutcome]],
    start: float,
) -> None:
    """One ``command_execution`` trace per asset-backed target with its outcome,
    scoped to the asset through ``execution_context_identifiers`` so the platform
    lists it under that target. A target without an asset (manual target) gets a
    trace only when it was not scanned; its other outcomes are in the global counts.
    The ``complete`` callback stays global and is sent by the caller.
    """
    logger = helper.injector_logger
    sent = 0
    for outcome in outcomes or []:
        asset_id = outcome.resolution.asset_id
        if not asset_id and outcome.scanned:
            continue
        message = outcome.describe()
        data = {
            "execution_message": message,
            "execution_status": outcome.status,
            "execution_duration": int(time.time() - start),
            "execution_action": "command_execution",
        }
        if asset_id:
            data["execution_context_identifiers"] = [asset_id]
        if outcome.scanned:
            logger.debug(message)
        else:
            logger.warning(message)
        try:
            helper.api.inject.execution_callback(inject_id=inject_id, data=data)
            sent += 1
        except Exception as exc:  # noqa: BLE001
            # A 404 means the inject was deleted: stop at the first one.
            if is_inject_gone(exc):
                raise InjectGoneError(inject_id, exc) from exc
            logger.error(
                f"Failed to send the target outcome trace for inject {inject_id} "
                f"(target '{outcome.resolution.target}'): {exc}"
            )
    if sent:
        logger.info(f"Sent {sent} target outcome trace(s) for inject {inject_id}")


def send_skipped_asset_traces(
    helper: OpenAEVInjectorHelper,
    inject_id: str,
    skipped: Optional[Iterable[SkippedAsset]],
    start: float,
) -> int:
    """One ``WARNING`` ``command_execution`` trace per asset that got no target value
    (so it was never scanned), on that asset, with the reason and the target property:
    '<asset>: not scanned, <reason> (target property <selector>)'. Returns the number of
    traces sent. The injector logger line written at extraction stays."""
    logger = helper.injector_logger
    sent = 0
    for asset in skipped or []:
        data = {
            "execution_message": _cap(asset.describe()),
            "execution_status": WARNING,
            "execution_duration": int(time.time() - start),
            "execution_action": "command_execution",
        }
        if asset.asset_id:
            data["execution_context_identifiers"] = [asset.asset_id]
        try:
            helper.api.inject.execution_callback(inject_id=inject_id, data=data)
            sent += 1
        except Exception as exc:  # noqa: BLE001
            logger.error(
                f"Failed to send the skipped asset trace for inject {inject_id} "
                f"(asset '{asset.asset_label()}'): {exc}"
            )
    if sent:
        logger.info(f"Sent {sent} skipped asset trace(s) for inject {inject_id}")
    return sent


def send_scan_progress_trace(
    helper: OpenAEVInjectorHelper,
    inject_id: str,
    target_count: int,
    *,
    label: str,
    start: float,
) -> None:
    """INFO trace before a batch run: how many targets it covers, and the platform
    timeout a long run may hit (a result sent after it is recorded, but the inject
    keeps the timed-out error status)."""
    if target_count <= 0:
        return
    try:
        helper.api.inject.execution_callback(
            inject_id=inject_id,
            data={
                "execution_message": (
                    f"{label}: {target_count} target(s) in one run. The platform "
                    f"finalizes an inject still running after {THRESHOLD_SETTING} "
                    "(default 10) as timed out; a result sent later is recorded but "
                    "the inject stays in error. For a large group, raise that "
                    "threshold or split the group."
                ),
                "execution_status": INFO,
                "execution_duration": int(time.time() - start),
                "execution_action": "command_execution",
            },
        )
    except Exception as exc:  # noqa: BLE001
        # A 404 means the inject was deleted: the caller aborts before the run.
        if is_inject_gone(exc):
            raise InjectGoneError(inject_id, exc) from exc
        helper.injector_logger.error(
            f"Failed to send the progress trace for inject {inject_id}: {exc}"
        )
