import json
import subprocess
import time
from typing import Dict

from injector_common.constants import TARGET_PROPERTY_SELECTOR_KEY, TARGET_SELECTOR_KEY
from injector_common.dump_config import intercept_dump_argument
from injector_common.targets import TargetProperty, Targets
from pyoaev.helpers import OpenAEVConfigHelper, OpenAEVInjectorHelper
from pyoaev.signatures import (
    SignatureManager,
    build_network_configs,
)

from nuclei.configuration.config_loader import ConfigLoader
from nuclei.helpers.nuclei_command_builder import NucleiCommandBuilder
from nuclei.helpers.nuclei_output_parser import NucleiOutputParser
from nuclei.helpers.nuclei_process import NucleiProcess
from nuclei.nuclei_contracts.external_contracts import ExternalContractsScheduler


class OpenAEVNuclei:
    def __init__(self):
        self.config = OpenAEVConfigHelper.from_configuration_object(
            ConfigLoader().to_daemon_config()
        )
        intercept_dump_argument(self.config.get_config_obj())
        self.helper = OpenAEVInjectorHelper(
            self.config, open("nuclei/img/nuclei.jpg", "rb")
        )

        if not self._check_nuclei_installed():
            raise RuntimeError(
                "Nuclei is not installed or is not accessible from your PATH."
            )
        self.command_builder = NucleiCommandBuilder()
        self.parser = NucleiOutputParser()

        self.inject_id = ""
        self.contract_id = ""
        self.inject_content = {}
        self.selector_key = ""
        self.selector_property = ""
        self.expectation_types = []

        self.assets = []
        self.asset_groups = []

    def _extract_targets(self, data: Dict):
        # Extract Targets
        target_results = Targets.extract_targets(
            self.selector_key, self.selector_property, data, self.helper
        )

        # Deduplicate targets
        targets = target_results.targets

        # Handle empty targets as an error
        if not targets:
            message = f"No target identified for the property {TargetProperty[self.selector_property.upper()].value}"
            raise ValueError(message)

        return target_results, targets

    def nuclei_execution(
        self, start: float, data: Dict, target_results, targets
    ) -> Dict:

        # Build Arguments to execute
        nuclei_args = self.command_builder.build_args(
            self.contract_id, self.inject_content, targets
        )
        input_data = "\n".join(targets).encode("utf-8")

        self.helper.injector_logger.info(
            "Executing nuclei with: " + " ".join(nuclei_args)
        )

        callback_data = {
            "execution_message": Targets.build_execution_message(
                selector_key=self.selector_key,
                data=data,
                command_args=nuclei_args,
            ),
            "execution_status": "INFO",
            "execution_duration": int(time.time() - start),
            "execution_action": "command_execution",
        }

        self.helper.api.inject.execution_callback(
            inject_id=self.inject_id,
            data=callback_data,
        )

        result = NucleiProcess.nuclei_execute(nuclei_args, input_data)
        return self.parser.parse(
            result.stdout.decode("utf-8"), target_results.ip_to_asset_id_map
        )

    def process_message(self, data: Dict) -> None:
        start = time.time()

        data_injection = data.get("injection", {})
        data_injector_contract = data_injection.get("inject_injector_contract", {})

        self.contract_id = data_injector_contract.get("convertedContent", {}).get(
            "contract_id"
        )
        self.inject_id = data_injection.get("inject_id")
        self.inject_content = data_injection.get("inject_content", {})
        self.selector_key = self.inject_content.get(TARGET_SELECTOR_KEY)
        self.selector_property = self.inject_content.get(TARGET_PROPERTY_SELECTOR_KEY)

        # Retrieving expectation_types
        expectations_content = self.inject_content.get("expectations")
        self.expectation_types = [
            item.get("expectation_type") for item in expectations_content
        ]

        # Triggering by assets / asset_groups
        self.assets = data.get("assets", [])
        self.asset_groups = data.get("assetGroups", [])

        # Notify API of reception and expected number of operations
        reception_data = {"tracking_total_count": 1}
        self.helper.api.inject.execution_reception(
            inject_id=self.inject_id, data=reception_data
        )

        # Injector Signature Manager
        signature_manager = SignatureManager(self.helper.api)

        target_results, targets = self._extract_targets(data)
        configs = build_network_configs(targets)

        # Compile pre-execution signatures
        pre_signatures = signature_manager.compile_pre_execution_signatures(
            config=configs
        )

        # Execute inject
        try:

            execution_result = self.nuclei_execution(
                start, data, target_results, targets
            )
            execution_message = execution_result.get("message")
            execution_result_outputs = execution_result.get("outputs")
            execution_status = "SUCCESS"
            tool_output = {}

        except Exception as e:

            execution_result = None
            execution_result_outputs = None
            execution_message = str(e)
            execution_status = "ERROR"
            tool_output = {"error_info": {"exit_code": 1}}

        callback_data = {
            "execution_message": execution_message,
            "execution_status": execution_status,
            "execution_duration": int(time.time() - start),
            "execution_action": "complete",
        }

        if execution_result:
            callback_data["execution_result"] = execution_result
        if execution_result_outputs:
            callback_data["execution_output_structured"] = json.dumps(
                execution_result_outputs
            )

        self.helper.api.inject.execution_callback(
            inject_id=self.inject_id, data=callback_data
        )

        # Compile post-execution signatures
        post_signatures = signature_manager.compile_post_execution_signatures(
            pre_signatures=pre_signatures,
            tool_output=tool_output,
        )

        # Build payload with extra
        expectation_signatures = signature_manager.build_payload(
            post_signatures=post_signatures,
            expectation_types=self.expectation_types,
            extra_signature={
                "vulnerability": {
                    "cves_tested": [],
                    "cves_found_vulnerable": [],
                }
            },
        )

        # Send signature to backend
        signature_manager.send_signatures(
            inject_id=self.inject_id,
            phase="execution_complete",
            signatures=expectation_signatures,
        )

    @staticmethod
    def _check_nuclei_installed():
        try:
            NucleiProcess.nuclei_version()
            return True
        except (FileNotFoundError, subprocess.CalledProcessError):
            return False

    def start(self):
        self.helper.listen(message_callback=self.process_message)
        ExternalContractsScheduler(
            self.helper.api,
            self.config.get_conf("injector_id"),
            self.config.get_conf(
                "injector_external_contracts_maintenance_schedule_seconds"
            ),
            self.helper.injector_logger,
        ).start()


if __name__ == "__main__":
    OpenAEVNuclei().start()
