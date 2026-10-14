"""Tests for the OpenAEVInjectorHelper (API client injected)."""

from unittest.mock import MagicMock, patch

import pytest
from xtm_oaev_sdk import Configuration, OpenAEVError

from injectors_sdk import OpenAEVConfigHelper, OpenAEVInjectorHelper

HINTS = {
    "injector_id": {"data": "injector-id"},
    "injector_name": {"data": "My injector"},
    "injector_type": {"data": "openaev_my_injector"},
    "injector_contracts": {"data": ["contract"]},
    "injector_log_level": {"data": "info"},
    "injector_json_logging": {"data": False},
}


def _given_config() -> OpenAEVConfigHelper:
    return OpenAEVConfigHelper.from_configuration_object(
        Configuration(config_hints=HINTS)
    )


@patch("xtm_oaev_sdk.PingAlive.start")
def test_registers_the_injector_with_its_icon_and_starts_the_heartbeat(
    mock_ping_start,
) -> None:
    """It registers through the injected client and starts PingAlive."""
    api = MagicMock()
    icon = MagicMock()

    helper = OpenAEVInjectorHelper(_given_config(), icon, api_client=api)

    assert helper.api is api
    config, injector_icon = api.injector.create.call_args.args
    assert config["injector_id"] == "injector-id"
    assert config["injector_custom_contracts"] is False
    assert injector_icon == ("openaev_my_injector.png", icon, "image/png")
    assert helper.injector_config is api.injector.create.return_value
    mock_ping_start.assert_called_once()


def test_without_api_client_raises() -> None:
    """It requires an injected client unless the hook is overridden."""
    with pytest.raises(OpenAEVError):
        OpenAEVInjectorHelper(_given_config(), MagicMock())


@patch("xtm_oaev_sdk.PingAlive.start")
def test_hook_builds_the_api_client_when_none_is_injected(_) -> None:
    """It lets client libraries provide the default client."""
    api = MagicMock()

    class _Helper(OpenAEVInjectorHelper):
        def _create_default_api_client(self, config):
            return api

    assert _Helper(_given_config(), MagicMock()).api is api


@patch("injectors_sdk._core.helpers.injector_helper.ListenQueue")
@patch("xtm_oaev_sdk.PingAlive.start")
def test_listen_starts_the_queue_listener(_, mock_listen_queue) -> None:
    """It hands the callback to a started ListenQueue."""
    helper = OpenAEVInjectorHelper(_given_config(), MagicMock(), api_client=MagicMock())
    callback = MagicMock()

    helper.listen(callback)

    mock_listen_queue.assert_called_once_with(
        helper.config, helper.injector_config, helper.injector_logger, callback
    )
    mock_listen_queue.return_value.start.assert_called_once()
