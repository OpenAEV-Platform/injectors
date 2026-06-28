"""Per-inject canary marker used to (a) detect attack success in the model response and (b) let AI
defense collectors correlate a guardrail/firewall event back to a specific inject execution.

The marker is deterministic per (inject_id, agent_id) so the platform-side expectation signatures and
the collector-side log matching agree without extra coordination.
"""

import hashlib

try:
    # Single source of truth shared with the AI defense collectors.
    from pyoaev.signatures.ai_marker import build_marker as _shared_build_marker
except ImportError:  # pragma: no cover - older pyoaev fallback
    _shared_build_marker = None


def build_marker(inject_id: str, agent_id: str = "") -> str:
    if _shared_build_marker is not None:
        return _shared_build_marker(inject_id, agent_id)
    seed = f"{inject_id}:{agent_id}".encode("utf-8")
    return "oaev" + hashlib.sha256(seed).hexdigest()[:16]


def request_header(marker: str) -> dict:
    # Sent on the outbound request so an in-line AI gateway/firewall can log and a collector can match
    return {"X-OAEV-Inject-Marker": marker}
