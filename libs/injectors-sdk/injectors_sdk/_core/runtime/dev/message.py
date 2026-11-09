"""Inject messages in dev mode: complete a lean message the way the platform fills it.

A lean message holds only the platform keys someone edits (the contract id, the
content, the targets). The rest is what the platform fills from data dev mode already
holds: the contract (``injector_contract_content`` and ``convertedContent``, from the
injector's own), the inject id and title, and the content defaults.

The content defaults follow the platform's inject form (``InjectForm.tsx``), which is
where injects are written: every content field (not a target, team, article,
challenge, attachment or credential reference) gets its contract default, the first
item for a single-value field; expectations default to the predefined available ones.
Unlike the form, which writes ``''`` for a falsy default, a default is kept as
declared (``false`` stays ``false``), and an empty list or object is left out.
"""

import copy
import json
import uuid
from typing import Any

__all__ = [
    "complete_message",
    "contract_content",
    "contract_fields",
    "label_of",
    "new_inject_content",
]

_NOT_DYNAMIC = frozenset({"teams", "articles", "challenges", "attachments"})
#: Field types that travel next to the content (``isInjectContentType`` of the form).
_NOT_CONTENT_TYPES = frozenset(
    {
        "asset",
        "team",
        "asset-group",
        "article",
        "challenge",
        "attachment",
        "credential-reference",
    }
)


def contract_content(contract: dict[str, Any]) -> dict[str, Any]:
    """The parsed ``contract_content`` of an injector contract."""
    content = contract.get("contract_content")
    return json.loads(content) if isinstance(content, str) else dict(content or {})


def contract_fields(contract: dict[str, Any]) -> list[dict[str, Any]]:
    """The fields of an injector contract, as the platform serializes them."""
    fields = contract_content(contract).get("fields", [])
    return [field for field in fields if isinstance(field, dict)]


def label_of(contract: dict[str, Any]) -> str:
    """The English label of a contract, else its first one."""
    labels = contract.get("contract_labels") or {}
    return str(labels.get("en") or next(iter(labels.values()), "") or "")


def _default(field: dict[str, Any]) -> Any:
    value = field.get("defaultValue")
    if field.get("key") == "expectations":
        available = field.get("availableExpectations")
        if isinstance(available, list):
            predefined = [
                e
                for e in available
                if isinstance(e, dict) and e.get("expectation_is_predefined")
            ]
            value = predefined or value
    if value is None or (isinstance(value, (list, dict)) and not value):
        return None
    if field.get("cardinality") == "1" and isinstance(value, list):
        return value[0]
    return value


def new_inject_content(contract: dict[str, Any]) -> dict[str, Any]:
    """The content the platform's inject form writes for a new inject of
    ``contract``: each content field's default."""
    content: dict[str, Any] = {}
    for field in contract_fields(contract):
        key = field.get("key")
        if not key or key in _NOT_DYNAMIC or field.get("type") in _NOT_CONTENT_TYPES:
            continue
        value = _default(field)
        if value is not None:
            content[key] = value
    return content


def complete_message(
    document: dict[str, Any], contract: dict[str, Any]
) -> dict[str, Any]:
    """``document`` completed with what the platform fills: the injector's own contract,
    an inject id and title, the content defaults under the content given. A whole
    message keeps every value it carries."""
    message = copy.deepcopy(document)
    injection = message["injection"]
    injection.setdefault("inject_id", str(uuid.uuid4()))
    injection.setdefault("inject_title", label_of(contract))
    injection.setdefault("inject_documents", [])
    reference = injection["inject_injector_contract"]
    reference.setdefault("injector_contract_content", contract.get("contract_content"))
    reference.setdefault("convertedContent", contract_content(contract))
    given = injection.get("inject_content") or {}
    injection["inject_content"] = {**new_inject_content(contract), **given}
    message.setdefault("assets", [])
    message.setdefault("assetGroups", [])
    message.setdefault("attachments", None)
    return message
