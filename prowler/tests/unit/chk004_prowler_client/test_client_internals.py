"""Focused unit contract for CHK.004 parser and in-memory backend."""

# ruff: noqa: D103

import importlib
from typing import Any

import pytest


def _api() -> Any:
    try:
        return importlib.import_module("prowler._core.client")
    except ModuleNotFoundError:
        pytest.fail("canonical prowler._core.client API is absent")


def test_parser_rejects_invalid_utf8_with_safe_context() -> None:
    api = _api()
    with pytest.raises(api.ProwlerClientError) as raised:
        api.parse_ocsf_output(b"\xffsecret")
    assert raised.value.code == "invalid_ocsf_output"
    assert raised.value.details == {"format": "utf-8", "reason": "invalid_encoding"}
    assert "secret" not in repr(raised.value)


@pytest.mark.parametrize("payload", ["", "[]", "1", '"record"', "{}\n[]"])
def test_parser_rejects_empty_or_non_record_documents(payload: str) -> None:
    api = _api()
    with pytest.raises(api.ProwlerClientError) as raised:
        api.parse_ocsf_output(payload)
    assert raised.value.code == "invalid_ocsf_output"
    if payload:
        assert payload not in repr(raised.value)


def test_backend_is_explicit_process_local_state_without_automatic_progress() -> None:
    api = _api()
    backend = api.InMemoryAssessmentBackend()
    handle = api.AssessmentHandle("assessment-test")
    request = api.AssessmentRequest(
        provider="provider-context",
        executable_path="/bin/prowler",
        check_filters=("a",),
    )

    backend.start(handle, request)
    assert backend.poll(handle).state == "queued"
    assert backend.poll(handle).state == "queued"
    backend.set_state(handle, "running")
    assert backend.poll(handle).state == "running"
