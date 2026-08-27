"""Regression tests for temporary credential lease lifetime."""

# ruff: noqa: D101, D102, D103

from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from pydantic import SecretStr

import prowler._core.prowler_client.client as client_module
from prowler._core.prowler_client import (
    CredentialCleanupError,
    ProwlerClient,
    TemporaryCredentialLeaseFactory,
)
from prowler.models.configs.config_loader import ProwlerConfig
from prowler.models.provider_inputs import AwsProviderInput


@dataclass
class _Lease:
    failure: BaseException | None = None
    cleanup_calls: int = 0

    def cleanup(self) -> None:
        self.cleanup_calls += 1
        if self.failure is not None:
            raise self.failure


@dataclass
class _Adapter:
    lease: _Lease

    def adapt(self, _provider: AwsProviderInput) -> Any:
        return SimpleNamespace(
            arguments=("aws", "-M", "json-ocsf"),
            environment={},
            credential_leases=(self.lease,),
        )


@dataclass
class _Engine:
    result: Any = None
    failure: BaseException | None = None

    def run(self, _request: Any) -> Any:
        if self.failure is not None:
            raise self.failure
        return self.result


def _provider() -> AwsProviderInput:
    return AwsProviderInput(
        provider="aws",
        aws_access_key_id="AKIA_TEST",
        aws_secret_access_key=SecretStr("secret"),
        aws_account_id="123456789012",
        aws_region="eu-west-1",
    )


def _client(lease: _Lease, engine: _Engine) -> ProwlerClient:
    return ProwlerClient(
        config=ProwlerConfig(executable_path="/opt/prowler/bin/prowler"),
        provider=_provider(),
        engine=engine,
        provider_adapter=cast(Any, _Adapter(lease)),
    )


def test_credential_file_is_created_owner_only(tmp_path: Path) -> None:
    lease = TemporaryCredentialLeaseFactory(temporary_root=tmp_path).create(
        SecretStr("credential"), suffix=".json"
    )
    try:
        assert lease.path.stat().st_mode & 0o777 == 0o600
        assert lease.directory.stat().st_mode & 0o777 == 0o700
        assert lease.path.read_text(encoding="utf-8") == "credential"
    finally:
        lease.cleanup()


def test_cleanup_removes_file_and_directory_idempotently(tmp_path: Path) -> None:
    lease = TemporaryCredentialLeaseFactory(temporary_root=tmp_path).create(
        SecretStr("credential"), suffix=".yaml"
    )

    lease.cleanup()
    lease.cleanup()

    assert not lease.path.exists()
    assert not lease.directory.exists()


def test_lease_is_released_when_engine_succeeds() -> None:
    lease = _Lease()
    result = object()

    assert _client(lease, _Engine(result=result)).run() is result
    assert lease.cleanup_calls == 1


def test_lease_is_released_when_engine_fails() -> None:
    lease = _Lease()
    primary = RuntimeError("safe engine failure")

    with pytest.raises(RuntimeError) as caught:
        _client(lease, _Engine(failure=primary)).run()

    assert caught.value is primary
    assert lease.cleanup_calls == 1


def test_lease_is_released_when_request_construction_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lease = _Lease()
    primary = RuntimeError("safe construction failure")

    def fail_construction(**_kwargs: Any) -> Any:
        raise primary

    monkeypatch.setattr(client_module, "ValidatedCommandRequest", fail_construction)

    with pytest.raises(RuntimeError) as caught:
        _client(lease, _Engine()).run()

    assert caught.value is primary
    assert lease.cleanup_calls == 1


def test_cleanup_failure_without_primary_error_is_safe() -> None:
    lease = _Lease(failure=OSError("unsafe cleanup detail"))

    with pytest.raises(CredentialCleanupError) as caught:
        _client(lease, _Engine(result=object())).run()

    assert str(caught.value) == "temporary credential cleanup failed"


def test_cleanup_failure_preserves_primary_error_and_adds_safe_note() -> None:
    lease = _Lease(failure=OSError("unsafe cleanup detail"))
    primary = RuntimeError("safe primary failure")

    with pytest.raises(RuntimeError) as caught:
        _client(lease, _Engine(failure=primary)).run()

    assert caught.value is primary
    assert caught.value.__notes__ == ["temporary credential cleanup also failed"]
