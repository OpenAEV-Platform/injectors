"""Fixtures local to the CHK.001 catalog scaffold behaviour tests."""

import pytest


@pytest.fixture
def standard_injector_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Configure the standard injector environment owned by CHK.001."""
    monkeypatch.setenv("OPENAEV_URL", "http://localhost:8080")
    monkeypatch.setenv("OPENAEV_TOKEN", "test-token")
    monkeypatch.setenv("OPENAEV_TENANT_ID", "test-tenant")
    monkeypatch.setenv("INJECTOR_ID", "test-injector")
    monkeypatch.setenv("INJECTOR_NAME", "Prowler")
    monkeypatch.setenv("INJECTOR_LOG_LEVEL", "debug")
