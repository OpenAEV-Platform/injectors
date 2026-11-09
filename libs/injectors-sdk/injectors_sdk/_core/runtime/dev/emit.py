"""Turns the signatures an injector posted in a dev run into the pending expectations
the platform would then serve to collectors (``InjectExpectationOutput``).

The signatures are read from the execution callbacks the injector posted, the
``expectation_signatures`` of their ``execution_output_structured``, the way the
platform's ``SignatureOutputProcessor`` reads them (openaev-platform,
``openaev-api/.../output_processor/SignatureOutputProcessor.java``):

- ``targets`` and each target's ``signature_values`` must be lists, else they are
  skipped; the target is the agent (``agent_id`` or ``agent``), else the asset
  (``asset_id`` or ``asset``), else the asset group (``asset_group_id`` or
  ``asset_group``), and a signature naming none is dropped
  (``InjectExpectationService.findTechnicalExpectationsForTarget``);
- an expectation type is trimmed and upper-cased, and must be an expectation type;
  signatures only attach to DETECTION and PREVENTION expectations
  (``appendExpectationSignatures``), and only to those the inject content declares
  (``inject_content.expectations``), the expectations the platform creates;
- a signature reads its type from ``signature_type`` or ``type`` and its value from
  ``signature_value`` or ``value``: the first scalar holding text, read as the platform
  reads it as text (``readText``); one without both is dropped, and a type and value
  pair is kept once.

An expectation without ``expectation_expiration_time`` expires after 21600 seconds
(``DEFAULT_TECHNICAL_EXPECTATION_EXPIRATION_TIME``). Expectations no signature attaches
to, which collectors cannot match, are left out. Dev mode has no expectation store:
every target a signature names is taken as a target of the inject.
"""

import json
import uuid
from datetime import datetime
from typing import Any

from xtm_oaev_sdk import InjectExpectationOutput

__all__ = ["pending_expectations", "posted_signatures"]

_SIGNED_TYPES = ("DETECTION", "PREVENTION")
#: ``BaseInjectExpectation.EXPECTATION_TYPE`` of the platform.
_EXPECTATION_TYPES = (
    "ARTICLE",
    "CHALLENGE",
    "MANUAL",
    "PREVENTION",
    "DETECTION",
    "LOGGING",
    "VULNERABILITY",
)
_DEFAULT_EXPIRATION_SECONDS = 21600


def _as_text(value: Any) -> str | None:
    """A JSON value node as the platform reads it as text (``JsonNode.asText``);
    ``None`` for a list or an object."""
    if isinstance(value, (list, dict)):
        return None
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _read_text(node: Any, *keys: str) -> str | None:
    """The first of ``keys`` holding a scalar with text (``readText``)."""
    if not isinstance(node, dict):
        return None
    for key in keys:
        if key not in node:
            continue
        text = _as_text(node[key])
        if text is not None and text.strip():
            return text
    return None


def posted_signatures(calls: list[dict[str, Any]], inject_id: str) -> list[Any]:
    """The ``expectation_signatures`` of the execution callbacks of ``inject_id``."""
    path = f"/api/injects/execution/callback/{inject_id}"
    posted = []
    for call in calls:
        body = call.get("body")
        if call.get("path") != path or not isinstance(body, dict):
            continue
        try:
            structured = json.loads(body.get("execution_output_structured") or "")
        except (TypeError, ValueError):
            continue
        if isinstance(structured, dict) and "expectation_signatures" in structured:
            posted.append(structured["expectation_signatures"])
    return posted


def _expected(content: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    expected: dict[str, dict[str, Any]] = {}
    for expectation in (content or {}).get("expectations") or []:
        if isinstance(expectation, dict):
            kind = str(expectation.get("expectation_type") or "").upper()
            expected.setdefault(kind, expectation)
    return expected


def _expectation_type(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    kind = value.strip().upper()
    return kind if kind in _EXPECTATION_TYPES else None


def _signatures(values: Any) -> list[tuple[str, str]]:
    if not isinstance(values, list):
        return []
    found = []
    for item in values:
        name = _read_text(item, "signature_type", "type")
        value = _read_text(item, "signature_value", "value")
        if name and value:
            found.append((name, value))
    return found


def pending_expectations(
    inject_id: str,
    inject_content: dict[str, Any] | None,
    posted: list[Any],
    created_at: datetime,
) -> tuple[list[dict[str, Any]], list[str]]:
    """The pending expectations of the run, and the notes about what the platform
    would have dropped."""
    expected = _expected(inject_content)
    notes: list[str] = []
    buckets: dict[tuple, list[tuple[str, str]]] = {}
    for payload in posted:
        targets = payload.get("targets") if isinstance(payload, dict) else None
        if not isinstance(targets, list):
            continue
        for target in targets:
            if not isinstance(target, dict):
                continue
            meta = target.get("signature_target")
            agent = _read_text(meta, "agent_id", "agent")
            asset = _read_text(meta, "asset_id", "asset")
            group = _read_text(meta, "asset_group_id", "asset_group")
            values = target.get("signature_values")
            if not isinstance(values, list):
                continue
            for group_values in values:
                if not isinstance(group_values, dict):
                    continue
                kind = _expectation_type(group_values.get("expectation_type"))
                signatures = _signatures(group_values.get("values"))
                if kind is None or not signatures:
                    continue
                if kind not in _SIGNED_TYPES:
                    notes.append(
                        f"{kind} signatures dropped: the platform attaches signatures"
                        " to detection and prevention expectations only"
                    )
                    continue
                if not (agent or asset or group):
                    notes.append(
                        "signatures dropped: they name no target (no agent, asset or"
                        " asset group, as with manual targets)"
                    )
                    continue
                if kind not in expected:
                    notes.append(
                        f"{kind} signatures dropped: the inject has no {kind}"
                        " expectation"
                    )
                    continue
                kept = buckets.setdefault((agent, asset, group, kind), [])
                kept.extend(pair for pair in signatures if pair not in kept)
    created = created_at.isoformat().replace("+00:00", "Z")
    pending = []
    for (agent, asset, group, kind), signatures in buckets.items():
        expectation = expected[kind]
        expiration = expectation.get("expectation_expiration_time")
        key = f"{inject_id}/{agent}/{asset}/{group}/{kind}"
        output = InjectExpectationOutput.model_validate(
            {
                "inject_expectation_id": str(uuid.uuid5(uuid.NAMESPACE_URL, key)),
                "inject_expectation_type": kind,
                "inject_expectation_name": expectation.get("expectation_name"),
                "inject_expectation_description": expectation.get(
                    "expectation_description"
                ),
                "inject_expectation_score": None,
                "inject_expectation_expected_score": expectation.get(
                    "expectation_score"
                ),
                "inject_expiration_time": (
                    _DEFAULT_EXPIRATION_SECONDS if expiration is None else expiration
                ),
                "inject_expectation_group": bool(
                    expectation.get("expectation_expectation_group")
                ),
                "inject_expectation_order": None,
                "inject_expectation_status": "PENDING",
                "inject_expectation_created_at": created,
                "inject_expectation_updated_at": created,
                "inject_expectation_signatures": [
                    {"type": name, "value": value} for name, value in signatures
                ],
                "inject_expectation_results": [],
                "inject_expectation_traces": [],
                "inject_expectation_exercise": None,
                "inject_expectation_inject": inject_id,
                "inject_expectation_user": None,
                "inject_expectation_team": None,
                "inject_expectation_agent": agent,
                "inject_expectation_asset": asset,
                "inject_expectation_asset_group": group,
                "inject_expectation_article": None,
                "inject_expectation_challenge": None,
                "target_id": agent or asset or group,
                "inject_expectation_expected_security_platforms": None,
                "inject_expectation_collector_missing_at_init": False,
            }
        )
        pending.append(json.loads(output.model_dump_json()))
    return pending, list(dict.fromkeys(notes))
