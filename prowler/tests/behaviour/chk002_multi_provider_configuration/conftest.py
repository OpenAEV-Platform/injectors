"""Fixtures local to CHK.002 multi-provider configuration behaviour."""

import pytest


@pytest.fixture
def standard_injector_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Configure the standard injector environment owned by CHK.001."""
    monkeypatch.setenv("OPENAEV_URL", "http://localhost:8080")
    monkeypatch.setenv("OPENAEV_TOKEN", "test-only-openaev-token")
    monkeypatch.setenv("OPENAEV_TENANT_ID", "00000000-0000-4000-8000-000000000002")
    monkeypatch.setenv("INJECTOR_ID", "test-prowler-injector")
    monkeypatch.setenv("INJECTOR_NAME", "Prowler")
    monkeypatch.setenv("INJECTOR_LOG_LEVEL", "debug")


@pytest.fixture
def clean_prowler_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure optional Prowler runtime settings are not overridden externally."""
    monkeypatch.delenv("PROWLER_EXECUTABLE_PATH", raising=False)
