"""Behaviour tests for the CHK.001 Prowler catalog scaffold."""

import json
from pathlib import Path
from typing import cast
from unittest.mock import Mock

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
