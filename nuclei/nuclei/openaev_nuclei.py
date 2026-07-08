import json
import subprocess
import time
from typing import Dict

from pyoaev.helpers import OpenAEVConfigHelper, OpenAEVInjectorHelper
from pyoaev.signatures import (
    ExtraSignatureData,
    SignatureManager,
    build_network_configs,
)
from pyoaev.signatures.models import ExecutionDetails

from injector_common.constants import TARGET_PROPERTY_SELECTOR_KEY, TARGET_SELECTOR_KEY
from injector_common.dump_config import intercept_dump_argument
from injector_common.targets import Targets
from nuclei.configuration.config_loader import ConfigLoader
from nuclei.helpers.nuclei_command_builder import NucleiCommandBuilder
from nuclei.helpers.nuclei_output_parser import NucleiOutputParser
from nuclei.helpers.nuclei_process import NucleiProcess
from nuclei.nuclei_contracts.external_contracts import ExternalContractsScheduler


class OpenAEVNuclei:
    def __init__(self):
        self.config_loader = ConfigLoader()
        self.config = OpenAEVConfigHelper.from_configuration_object(
            self.config_loader.to_daemon_config()
        )
        intercept_dump_argument(self.config.get_config_obj())
        self.helper = OpenAEVInjectorHelper(
            self.config, open("nuclei/img/nuclei.jpg", "rb")
        )

        if not self._check_nuclei_installed():
            raise RuntimeError(
                "Nuclei is not installed or is not accessible from your PATH."
            )
        self.parser = NucleiOutputParser()

        self.inject_id = ""
        self.contract_id = ""
        self.inject_content = {}
        self.selector_key = ""
        self.selector_property = ""
        self.expectation_types = []

    def _extract_targets(self, data: Dict):
        # Extract Targets
        target_results = Targets.extract_targets(
            self.selector_key, self.selector_property, data, self.helper
        )

        # Deduplicate targets
        targets = target_results.targets

        # Handle empty targets as an error
        if not targets:
            if self.selector_property:
                message = f"No target identified for the property {self.selector_property.upper()}"
            else:
                message = "No target identified, empty/missing selector property"
            raise ValueError(message)

        return target_results, targets

    def _extract_targets_meta(self, data: dict):
        return Targets.extract_target_meta(
            self.selector_key, self.selector_property, data, self.helper
        )

    def nuclei_execution(
        self, start: float, data: Dict, target_results, targets
    ) -> Dict:
        # Nuclei Args Builder
        nuclei_builder = NucleiCommandBuilder(
            nuclei_configs=self.config_loader.nuclei,
            contract_id=self.contract_id,
            content=self.inject_content,
            targets=targets,
        )
        nuclei_args = nuclei_builder.build()

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

        input_data = ("\n".join(targets) + "\n").encode("utf-8")
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
        expectations_content = self.inject_content.get("expectations") or []
        self.expectation_types = [
            item.get("expectation_type")
            for item in expectations_content
            if item.get("expectation_type")
        ]

        # Notify API of reception and expected number of operations
        reception_data = {"tracking_total_count": 1}
        self.helper.api.inject.execution_reception(
            inject_id=self.inject_id, data=reception_data
        )

        # Injector Signature Manager
        signature_manager = SignatureManager(self.helper.api)

        execution_details = ExecutionDetails()

        pre_execute_fail_flag = False
        pre_execute_fail_message = ""

        try:
            target_results, targets = self._extract_targets(data)
        except Exception as e:
            pre_execute_fail_flag = True
            pre_execute_fail_message = (
                f"Could not extract targets: {type(e).__name__} - {e}"
            )
        else:
            try:
                configs = build_network_configs(targets)
            except Exception as e:
                pre_execute_fail_flag = True
                pre_execute_fail_message = (
                    f"Could not build network configurations: {type(e).__name__} - {e}"
                )
            else:
                try:
                    # Compile pre-execution signatures
                    execution_signatures = signature_manager.build_execution_signatures(
                        config=configs
                    )
                except Exception as e:
                    pre_execute_fail_flag = True
                    pre_execute_fail_message = f"Could not build execution signatures: {type(e).__name__} - {e}"

        execution_result_outputs = None
        tool_output = {}
        execution_action = "complete"

        if pre_execute_fail_flag:
            execution_message = f"Pre-execution failure: {pre_execute_fail_message}"
            execution_status = "ERROR"
        else:
            # Execute inject
            try:
                execution_result = self.nuclei_execution(
                    start, data, target_results, targets
                )
                execution_message = execution_result.get("message")
                execution_result_outputs = execution_result.get("outputs")
                execution_status = "SUCCESS"
            except Exception as e:
                execution_message = str(e)
                execution_status = "ERROR"
                tool_output = {"error_info": {"exit_code": 1}}

        callback_data = {
            "execution_message": execution_message,
            "execution_status": execution_status,
            "execution_duration": int(time.time() - start),
            "execution_action": execution_action,
        }

        if execution_result_outputs:
            callback_data["execution_output_structured"] = json.dumps(
                execution_result_outputs
            )

        self.helper.api.inject.execution_callback(
            inject_id=self.inject_id, data=callback_data
        )

        if pre_execute_fail_flag:
            return

        # Compile post-execution signatures
        signature_manager.post_execution_updates(
            execution_details=execution_details,
            execution_signatures=execution_signatures,
            tool_output=tool_output,
        )

        # Build payload with extra
        expectation_signatures = signature_manager.build_payload(
            execution_signatures=execution_signatures,
            targets_meta=self._extract_targets_meta(data),
            expectation_types=self.expectation_types,
            extra_signatures=ExtraSignatureData(
                vulnerability={
                    "cves_tested": [],
                    "cves_found_vulnerable": [],
                }
            ),
        )

        # Send signature to backend
        signature_manager.send_signatures(
            inject_id=self.inject_id,
            execution_details=execution_details,
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
