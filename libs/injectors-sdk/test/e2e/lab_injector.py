"""A lab injector for the end-to-end tests: it pings a target with a command, sends
the signatures of the target, then completes the inject."""

import json
import subprocess
import sys
from unittest.mock import MagicMock

from injectors_sdk import OpenAEVConfigHelper, OpenAEVInjectorHelper
from xtm_oaev_sdk import (
    Configuration,
    ExecutionDetails,
    ExecutionStatus,
    InjectExecutionActions,
    SignatureOutputStructure,
)

CONTRACT_ID = "5c8b6c3e-0000-4000-8000-0000000000e2"
CONTENT = {
    "contract_id": CONTRACT_ID,
    "fields": [
        {"key": "ip", "type": "text", "mandatory": True},
        {
            "key": "expectations",
            "type": "expectation",
            "mandatory": False,
            "availableExpectations": [
                {
                    "expectation_type": "DETECTION",
                    "expectation_name": "Ping detected",
                    "expectation_score": 100.0,
                    "expectation_is_predefined": True,
                }
            ],
        },
    ],
}
config = OpenAEVConfigHelper.from_configuration_object(
    Configuration(
        config_hints={
            "injector_id": {"data": "lab-injector"},
            "injector_name": {"data": "Lab ping"},
            "injector_type": {"data": "openaev_lab_ping"},
            "injector_log_level": {"data": "error"},
            "injector_json_logging": {"data": False},
            "lab_api_key": {"data": "lab-secret-123"},
            "injector_contracts": {
                "data": [
                    {
                        "contract_id": CONTRACT_ID,
                        "contract_labels": {"en": "Lab - Ping"},
                        "contract_content": json.dumps(CONTENT),
                    }
                ]
            },
        }
    )
)
helper = OpenAEVInjectorHelper(config, MagicMock())


def callback(data):
    inject_id = data["injection"]["inject_id"]
    ip = data["injection"]["inject_content"]["ip"]
    helper.api.inject.execution_reception(
        inject_id=inject_id, data={"tracking_total_count": 1}
    )
    out = subprocess.run(
        [sys.executable, "-c", f"print('pong {ip} key=lab-secret-123')"],
        capture_output=True,
        text=True,
    )
    sig = SignatureOutputStructure.model_validate(
        {
            "expectation_signatures": {
                "targets": [
                    {
                        "signature_target": {"asset": "asset-lab-1"},
                        "signature_values": [
                            {
                                "expectation_type": "DETECTION",
                                "values": [
                                    {
                                        "signature_type": "target_ipv4_address",
                                        "signature_value": ip,
                                    }
                                ],
                            }
                        ],
                    }
                ]
            }
        }
    )
    helper.api.signature.send_signatures(
        inject_id,
        sig,
        ExecutionDetails(
            execution_status=ExecutionStatus.EXECUTED,
            execution_action=InjectExecutionActions.DATA,
        ),
        max_payload_size=5 * 1024 * 1024,
        logger=MagicMock(),
    )
    helper.api.inject.execution_callback(
        inject_id=inject_id,
        data={
            "execution_message": out.stdout.strip(),
            "execution_status": "SUCCESS",
            "execution_action": "complete",
        },
    )


helper.listen(callback)
