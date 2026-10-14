"""Tests for the OpenAEVConfigHelper legacy configuration accessor."""

import pytest
from xtm_oaev_sdk import Configuration

from injectors_sdk import OpenAEVConfigHelper


def _given_helper(hints: dict) -> OpenAEVConfigHelper:
    return OpenAEVConfigHelper.from_configuration_object(
        Configuration(config_hints=hints)
    )


def test_get_conf_reads_the_configuration() -> None:
    """It returns the configured value."""
    helper = _given_helper({"injector_name": {"data": "nmap"}})
    assert helper.get_conf("injector_name") == "nmap"


def test_get_conf_falls_back_to_default() -> None:
    """It returns the default for a missing key."""
    helper = _given_helper({})
    assert helper.get_conf("injector_category", default="network") == "network"


def test_get_conf_raises_for_missing_required_key() -> None:
    """It raises when a required key has neither value nor default."""
    helper = _given_helper({})
    with pytest.raises(ValueError):
        helper.get_conf("injector_id", required=True)


def test_builds_configuration_from_hints_and_base_path(tmp_path) -> None:
    """It loads config.yml next to the given base path."""
    (tmp_path / "config.yml").write_text("injector:\n  name: from-file\n")
    helper = OpenAEVConfigHelper(
        str(tmp_path / "main.py"),
        {"injector_name": {"file_path": ["injector", "name"]}},
        None,
    )
    assert helper.get_conf("injector_name") == "from-file"
    assert isinstance(helper.to_configuration(), Configuration)
    assert helper.get_config_obj() is helper.to_configuration()
