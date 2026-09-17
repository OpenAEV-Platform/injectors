"""Shared selection helpers for selectable Prowler contracts."""

import threading
from collections.abc import Container, Mapping

from pydantic import ValidationError

from .base import (
    BaseProwlerContract,
    ClientFactoryPort,
    ContractInputError,
    ContractInputIssue,
)


def parse_compliance_literal(literal: str) -> tuple[str, str]:
    """Split one CHK.004 compliance literal into its route components."""
    provider = literal.rsplit("_", maxsplit=1)[1]
    framework = literal.rsplit("_", maxsplit=1)[0].split("_", maxsplit=1)[0]
    return framework, provider


def forbid_provider_key(raw_input: Mapping[str, object]) -> None:
    """Reject the provider model discriminator in contract form input."""
    if "provider" in raw_input:
        raise selection_input_error(("provider",), "extra_forbidden")


def parse_closed_select(
    raw_input: Mapping[str, object],
    key: str,
    options: Container[str],
    *,
    required: bool,
    none_value: str | None = None,
) -> str | None:
    """Validate one closed, single-choice select without retaining its value."""
    if key not in raw_input:
        if not required:
            return None
        submitted: object = None
    else:
        submitted = raw_input[key]
    if submitted is None or submitted == "" or submitted == []:
        if not required:
            return None
        raise selection_input_error((key,), "select_missing")
    if isinstance(submitted, list):
        if len(submitted) > 1:
            raise selection_input_error((key,), "select_multiple")
        element = submitted[0]
    else:
        element = submitted
    if none_value is not None and element == none_value:
        return None
    if type(element) is not str or element not in options:
        raise selection_input_error((key,), "select_unknown_value")
    return element


def selection_input_error(
    location: tuple[str, ...], error_type: str
) -> ContractInputError:
    """Build the single value-free issue for one select rejection."""
    return ContractInputError.from_validation(
        (ContractInputIssue(location, error_type),)
    )


def translate_validation_error(error: ValidationError) -> ContractInputError:
    """Translate strict provider-model validation into contract input issues."""
    issues = tuple(
        ContractInputIssue(
            tuple(str(part) for part in item["loc"]),
            item["type"],
        )
        for item in error.errors(
            include_url=False, include_context=False, include_input=False
        )
    )
    return ContractInputError.from_validation(issues)


class SelectionScopedContract(BaseProwlerContract):
    """Keep parsed selections private to the worker processing one injection."""

    def __init__(self, client_factory: ClientFactoryPort | None = None) -> None:
        """Start with no worker thread holding a selection."""
        super().__init__(client_factory)
        self._selection = threading.local()

    def _clear_selection(self, *names: str) -> None:
        """Clear every retained selection before a new parse can reject."""
        for name in names:
            setattr(self._selection, name, None)
