"""Executable behaviour contract for CHK.004."""

# ruff: noqa: D103

import importlib
from pathlib import Path
from typing import Any

import pytest

from prowler.models.configs.config_loader import ProwlerConfig
from prowler.models.provider_inputs import AwsProviderInput


def _api() -> Any:
    try:
        return importlib.import_module("prowler._core.client")
    except ModuleNotFoundError:
        pytest.fail("canonical prowler._core.client API is absent")


def _client(api: Any, provider_input: AwsProviderInput) -> tuple[Any, Any]:
    backend = api.InMemoryAssessmentBackend()
    client = api.ProwlerClient(
        provider=provider_input,
        config=ProwlerConfig(executable_path="/opt/prowler/bin/prowler"),
        backend=backend,
    )
    return client, backend


def test_start_returns_handle_and_preserves_filters(
    provider_input: AwsProviderInput,
) -> None:
    api = _api()
    client, backend = _client(api, provider_input)

    handle = client.start_scan(("check-z", "check-a", "check-z"))

    assert isinstance(handle, api.AssessmentHandle)
    assert handle.value
    assert backend.request_for(handle).check_filters == (
        "check-z",
        "check-a",
        "check-z",
    )
    assert client.executable_path == Path("/opt/prowler/bin/prowler")


@pytest.mark.parametrize(
    "state", ["queued", "running", "succeeded", "failed", "cancelled"]
)
def test_poll_reports_each_explicit_state(
    provider_input: AwsProviderInput, state: str
) -> None:
    api = _api()
    client, backend = _client(api, provider_input)
    handle = client.start_scan(("check-1",))
    error = api.ProwlerClientError("assessment_failed", "failed", {"exit_code": 2})
    backend.set_state(handle, state, error=error if state == "failed" else None)

    status = client.poll_scan(handle)

    assert status.state == state
    assert (status.error is error) is (state == "failed")


def test_invalid_filters_are_structured(provider_input: AwsProviderInput) -> None:
    api = _api()
    client, _ = _client(api, provider_input)

    for filters in ((), ("",), ("  ",), ("ok", 7)):
        with pytest.raises(api.ProwlerClientError) as raised:
            client.start_scan(filters)
        assert raised.value.code == "invalid_check_filters"
        assert raised.value.message
        assert raised.value.details


def test_unknown_and_malformed_handles_are_structured(
    provider_input: AwsProviderInput,
) -> None:
    api = _api()
    client, _ = _client(api, provider_input)

    for handle in (
        "not-a-handle",
        api.AssessmentHandle(""),
        api.AssessmentHandle("other"),
    ):
        with pytest.raises(api.ProwlerClientError) as raised:
            client.poll_scan(handle)
        assert raised.value.code in {"invalid_assessment_handle", "unknown_assessment"}
        assert raised.value.details


def test_parser_accepts_json_array_and_json_lines_in_order(
    provider_input: AwsProviderInput,
) -> None:
    api = _api()
    client, _ = _client(api, provider_input)
    expected = [{"id": 2}, {"id": 1}]

    assert client.parse_ocsf_output('[{"id": 2}, {"id": 1}]') == expected
    assert client.parse_ocsf_output(b'{"id": 2}\n\n{"id": 1}\n') == expected


@pytest.mark.parametrize("payload", ["{secret-token", '[{"ok": true}, 3]'])
def test_parser_errors_do_not_echo_payload_or_credentials(
    provider_input: AwsProviderInput, payload: str
) -> None:
    api = _api()
    client, _ = _client(api, provider_input)

    with pytest.raises(api.ProwlerClientError) as raised:
        client.parse_ocsf_output(payload)

    rendered = repr(raised.value)
    assert raised.value.code == "invalid_ocsf_output"
    assert payload not in rendered
    assert "secret-token" not in rendered
    assert "do-not-leak" not in rendered
