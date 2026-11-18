"""Contract helpers of dev mode: list an injector's contracts, write a lean inject
message to edit for one of them, with a guide to its fields.

The message is prefilled the way the platform's inject form fills a new inject (see
``message``), and its target type is switched to one dev mode can run.
"""

import json
from typing import Any

from .message import NOT_DYNAMIC_KEYS, contract_content, label_of, new_inject_content

__all__ = [
    "contract_lines",
    "field_guide",
    "find_contracts",
    "new_inject_message",
]


def contract_lines(contracts: list[dict[str, Any]]) -> list[str]:
    """One line per contract: its id, its label, and the targets it takes."""
    lines = []
    for contract in contracts:
        line = f"{contract.get('contract_id')}  {label_of(contract)}"
        selector = next(
            (
                f
                for f in contract_content(contract).get("fields", [])
                if f.get("key") == "target_selector"
            ),
            None,
        )
        if selector and selector.get("choices"):
            line += "  targets: " + ", ".join(selector["choices"])
        lines.append(line)
    return lines


def find_contracts(contracts: list[dict[str, Any]], name: str) -> list[dict[str, Any]]:
    """The contract whose id is ``name``, else those with ``name`` in a label."""
    exact = [c for c in contracts if c.get("contract_id") == name]
    if exact:
        return exact
    wanted = name.casefold()
    return [
        c
        for c in contracts
        if any(
            wanted in str(label).casefold()
            for label in (c.get("contract_labels") or {}).values()
        )
    ]


#: Target types dev mode can run, by preference: asset groups need the platform to
#: resolve their members (a target search), which dev mode cannot answer.
_RUNNABLE_TARGETS = ("manual", "assets")


def _runnable_target(content: dict[str, Any], contract: dict[str, Any]) -> str | None:
    """Switch an ``asset-groups`` target type to one dev mode can run; say so."""
    if content.get("target_selector") != "asset-groups":
        return None
    selector = next(
        (
            f
            for f in contract_content(contract).get("fields", [])
            if f.get("key") == "target_selector"
        ),
        {},
    )
    choice = next(
        (c for c in _RUNNABLE_TARGETS if c in (selector.get("choices") or {})), None
    )
    if choice is None:
        return None
    content["target_selector"] = choice
    return (
        f"target_selector set to {choice!r} instead of 'asset-groups': asset groups"
        " need the platform to resolve their assets"
    )


def new_inject_message(contract: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """A lean inject message for ``contract``, and the notes about its content."""
    content = new_inject_content(contract)
    note = _runnable_target(content, contract)
    message = {
        "injection": {
            "inject_content": content,
            "inject_injector_contract": {
                "injector_contract_id": contract.get("contract_id")
            },
        },
        "assets": [],
        "assetGroups": [],
    }
    return message, [note] if note else []


def _rule(field: dict[str, Any]) -> str:
    if field.get("mandatory"):
        return "mandatory"
    conditions = field.get("mandatoryConditionFields") or []
    values = field.get("mandatoryConditionValues") or {}
    if conditions:
        parts = []
        for condition in conditions:
            expected = values.get(condition) if isinstance(values, dict) else None
            if isinstance(expected, list):
                expected = "|".join(str(v) for v in expected)
            parts.append(f"{condition}={expected}" if expected else condition)
        return "when " + ", ".join(parts)
    if field.get("mandatoryGroups"):
        return "one of " + "|".join(field["mandatoryGroups"])
    return "optional"


_TARGET_HINTS = {
    "asset": "give them as `assets` of the message",
    "asset-group": "give them as `assetGroups` of the message (needs the platform)",
    "team": "give them as `inject_teams` of the injection",
}


def field_guide(contract: dict[str, Any], content: dict[str, Any]) -> list[str]:
    """One line per content field: key, type, when it is mandatory, value, choices."""
    lines = []
    for field in contract_content(contract).get("fields", []):
        key = field.get("key")
        if not key or key in NOT_DYNAMIC_KEYS:
            continue
        kind = str(field.get("type") or "")
        line = f"  {key:<26} {kind:<20} {_rule(field):<40}"
        if key in content:
            value = content[key]
            if key == "expectations" and isinstance(value, list):
                value = [
                    e.get("expectation_type") for e in value if isinstance(e, dict)
                ]
            line += f" = {json.dumps(value)}"
        if field.get("choices"):
            line += "  [" + " | ".join(field["choices"]) + "]"
        if kind in _TARGET_HINTS:
            line += "  " + _TARGET_HINTS[kind]
        lines.append(line.rstrip())
    return lines
