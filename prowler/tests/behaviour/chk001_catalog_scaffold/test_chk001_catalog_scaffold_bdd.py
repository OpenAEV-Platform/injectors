"""Behaviour tests for the CHK.001 Prowler catalog scaffold."""

import json
import logging
from pathlib import Path
from typing import cast
from unittest.mock import Mock

import pytest
from pydantic import BaseModel, ValidationError

from prowler import __main__ as prowler_main
from prowler.injector.openaev_prowler import ProwlerInjector
from prowler.models.configs.config_loader import ConfigLoader

PROJECT_ROOT = Path(__file__).parents[3]
STANDARD_ENV_SETTINGS = {
    "OPENAEV_URL",
    "OPENAEV_TOKEN",
    "OPENAEV_TENANT_ID",
    "INJECTOR_ID",
    "INJECTOR_NAME",
    "INJECTOR_LOG_LEVEL",
}
VALIDATION_CANARY = "PYDANTIC_VALIDATION_CANARY"
UNEXPECTED_CANARY = "UNEXPECTED_EXCEPTION_CANARY"
SENSITIVE_CANARIES = (VALIDATION_CANARY, UNEXPECTED_CANARY)


class _IntegerSetting(BaseModel):
    value: int


def _given_the_prowler_project() -> Path:
    assert (PROJECT_ROOT / "prowler").is_dir(), "Prowler package scaffold is absent"
    return PROJECT_ROOT


def _when_manifest_is_loaded(project_root: Path) -> dict[str, object]:
    manifest_path = project_root / "manifest-metadata.json"
    assert manifest_path.is_file(), "Prowler catalog manifest is absent"
    return cast(
        dict[str, object], json.loads(manifest_path.read_text(encoding="utf-8"))
    )


def _then_manifest_identifies_prowler(manifest: dict[str, object]) -> None:
    assert manifest["title"] == "Prowler"
    assert manifest["slug"] == "openaev_prowler"
    assert manifest["container_image"] == "openaev/injector-prowler"
    assert manifest["container_type"] == "INJECTOR"


def _when_sample_environment_is_loaded(project_root: Path) -> set[str]:
    sample_path = project_root / ".env.sample"
    assert sample_path.is_file(), "Prowler environment sample is absent"
    return {
        line.partition("=")[0]
        for raw_line in sample_path.read_text(encoding="utf-8").splitlines()
        if (line := raw_line.strip()) and not line.startswith("#") and "=" in line
    }


def _then_only_standard_settings_are_available(settings: set[str]) -> None:
    assert settings == STANDARD_ENV_SETTINGS


def _when_injector_starts() -> tuple[ConfigLoader, Mock]:
    config = ConfigLoader()
    helper = Mock()
    injector = ProwlerInjector(config=config, helper=helper)
    injector.start()
    return config, helper


def _then_zero_contracts_are_registered(config: ConfigLoader, helper: Mock) -> None:
    assert config.to_daemon_config().get("injector_contracts") == []
    callback = helper.listen.call_args.kwargs["message_callback"]
    assert callable(callback)


def _given_startup_failure(failure_type: str) -> Exception:
    if failure_type == "configuration error":
        try:
            _IntegerSetting(value=VALIDATION_CANARY)
        except ValidationError as error:
            return error
        raise AssertionError("Validation canary did not trigger a configuration error")
    return RuntimeError(UNEXPECTED_CANARY)


def _when_startup_failure_is_handled(
    error: Exception,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> tuple[int, list[logging.LogRecord]]:
    monkeypatch.setattr(prowler_main, "ConfigLoader", Mock(side_effect=error))

    with caplog.at_level(logging.DEBUG, logger=prowler_main.__name__):
        with pytest.raises(SystemExit) as raised:
            prowler_main.main()

    return cast(int, raised.value.code), list(caplog.records)


def _then_failure_is_logged_safely(
    actual_exit_status: int,
    expected_exit_status: int,
    records: list[logging.LogRecord],
) -> None:
    assert actual_exit_status == expected_exit_status
    error_records = [record for record in records if record.levelno == logging.ERROR]
    assert len(error_records) == 1

    for record in records:
        assert record.exc_info is None
        assert record.exc_text is None
        log_surfaces = (record.getMessage(), str(record.msg), repr(record.args))
        assert all(
            canary not in surface
            for canary in SENSITIVE_CANARIES
            for surface in log_surfaces
        )


def test_discoverable_prowler_catalog_registration() -> None:
    """Prowler is represented by a discoverable catalog manifest."""
    project_root = _given_the_prowler_project()
    manifest = _when_manifest_is_loaded(project_root)
    _then_manifest_identifies_prowler(manifest)


def test_foundation_configuration_excludes_future_provider_settings() -> None:
    """The foundation exposes only standard injector settings."""
    project_root = _given_the_prowler_project()
    settings = _when_sample_environment_is_loaded(project_root)
    _then_only_standard_settings_are_available(settings)


def test_foundation_startup_registers_no_assessment_contracts(
    standard_injector_environment: None,
) -> None:
    """The foundation starts its listener with an empty contract catalog."""
    _given_the_prowler_project()
    config, helper = _when_injector_starts()
    _then_zero_contracts_are_registered(config, helper)


@pytest.mark.parametrize(
    ("failure_type", "expected_exit_status"),
    (("configuration error", 2), ("unexpected exception", 1)),
)
def test_startup_failures_are_logged_without_sensitive_exception_details(
    failure_type: str,
    expected_exit_status: int,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Startup failures preserve safe logs and established exit statuses."""
    error = _given_startup_failure(failure_type)
    actual_exit_status, records = _when_startup_failure_is_handled(
        error, monkeypatch, caplog
    )
    _then_failure_is_logged_safely(actual_exit_status, expected_exit_status, records)
