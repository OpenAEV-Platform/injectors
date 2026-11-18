"""Parity of the emitted pending expectations with the platform's signature processing.

Feature: Emitted signatures follow the platform's signature processing
  Each case of ``fixtures/signature_processing_parity.json`` is one test of the
  platform's ``SignatureOutputProcessorTest``: the ``expectation_signatures`` an injector
  posts, and the expectations the platform signs with them. An injector posting the same
  structure in a dev run emits the same signed expectations.
"""

import io
import json
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from injectors_sdk import ListenQueue, OpenAEVConfigHelper, OpenAEVInjectorHelper
from xtm_oaev_sdk import Configuration

CONTRACT_ID = "5c8b6c3e-0000-4000-8000-000000000001"
CONTRACT = {
    "contract_id": CONTRACT_ID,
    "contract_labels": {"en": "TCP connect scan"},
    "contract_content": json.dumps(
        {
            "contract_id": CONTRACT_ID,
            "fields": [{"key": "targets", "type": "text", "mandatory": True}],
        }
    ),
}
INJECT_ID = "8a4f1f0e-2c4b-4f43-9d5e-0b6f5b6f1a01"
PARITY = json.loads(
    (Path(__file__).parent / "fixtures" / "signature_processing_parity.json").read_text(
        encoding="utf-8"
    )
)["cases"]


def _given_inject_message_file(tmp_path: Path) -> str:
    """Given an inject message declaring a DETECTION and a PREVENTION expectation"""
    message = {
        "injection": {
            "inject_id": INJECT_ID,
            "inject_content": {
                "targets": "127.0.0.1",
                "expectations": [
                    {"expectation_type": "DETECTION", "expectation_name": "Detected"},
                    {"expectation_type": "PREVENTION", "expectation_name": "Blocked"},
                ],
            },
            "inject_injector_contract": {"injector_contract_id": CONTRACT_ID},
        },
    }
    path = tmp_path / "inject.json"
    path.write_text(json.dumps(message))
    return str(path)


def _when_posting_and_emitting(path: str, posted: Any) -> list[dict[str, Any]]:
    """When the injector posts those expectation signatures in a dev run emitting
    expectations"""
    argv = ["openaev-port-scanner", "--dev", "--inject", path, "--emit", "expectations"]
    stdout, stderr = io.StringIO(), io.StringIO()
    configuration = OpenAEVConfigHelper.from_configuration_object(
        Configuration(
            config_hints={
                "injector_id": {"data": "4f1d-injector"},
                "injector_name": {"data": "Port scanner"},
                "injector_type": {"data": "openaev_port_scanner"},
                "injector_contracts": {"data": [CONTRACT]},
                "injector_log_level": {"data": "info"},
                "injector_json_logging": {"data": False},
            }
        )
    )

    def injector(helper: Any, data: dict[str, Any]) -> None:
        for body in (
            {
                "execution_message": "Signatures",
                "execution_output_structured": json.dumps(
                    {"expectation_signatures": posted}
                ),
                "execution_status": "SUCCESS",
                "execution_action": "data",
            },
            {
                "execution_message": "Scan done",
                "execution_status": "SUCCESS",
                "execution_action": "complete",
            },
        ):
            helper.api.inject.execution_callback(inject_id=INJECT_ID, data=body)

    with (
        patch.object(sys, "argv", argv),
        patch.object(sys, "stdout", stdout),
        patch.object(sys, "stderr", stderr),
        patch("xtm_oaev_sdk.PingAlive.start"),
        patch.object(
            ListenQueue,
            "start",
            side_effect=AssertionError("dev mode consumed the platform queue"),
        ),
    ):
        helper = OpenAEVInjectorHelper(configuration, MagicMock())
        with pytest.raises(SystemExit):
            helper.listen(lambda data: injector(helper, data))
    return json.loads(stdout.getvalue())


def _then_signed_are(pending: list[dict[str, Any]], expected: list[dict]) -> None:
    """Then the signed expectations are exactly those the platform signs"""
    signed = [
        {
            "type": e["inject_expectation_type"],
            "agent": e["inject_expectation_agent"],
            "asset": e["inject_expectation_asset"],
            "asset_group": e["inject_expectation_asset_group"],
            "signatures": [
                [s["type"], s["value"]] for s in e["inject_expectation_signatures"]
            ],
        }
        for e in pending
    ]
    key = lambda e: (e["type"], str(e["agent"]), str(e["asset"]))  # noqa: E731
    assert sorted(signed, key=key) == sorted(expected, key=key)


@pytest.mark.parametrize(
    "case", PARITY, ids=[case["source"].split(".")[-1] for case in PARITY]
)
def test_emitted_signatures_match_the_platform_processing(
    tmp_path: Path, case: dict[str, Any]
) -> None:
    """It signs exactly the expectations the platform signs, with the same signatures.

    Scenario Outline: Emitted signatures match the platform processing
      Given an inject message declaring a DETECTION and a PREVENTION expectation
      When the injector posts those expectation signatures in a dev run emitting expectations
      Then the signed expectations are exactly those the platform signs
    """
    path = _given_inject_message_file(tmp_path)
    pending = _when_posting_and_emitting(path, case["expectation_signatures"])
    _then_signed_are(pending, case["signed"])
