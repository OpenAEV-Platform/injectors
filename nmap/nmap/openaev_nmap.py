import json
import subprocess
import time

from pyoaev.helpers import OpenAEVConfigHelper, OpenAEVInjectorHelper
from pyoaev.signatures import SignatureManager
from pyoaev.signatures.models import (
    ExecutionDetails,
    ExtraSignatureData,
    build_network_configs,
)

from injector_common.constants import TARGET_PROPERTY_SELECTOR_KEY, TARGET_SELECTOR_KEY
from injector_common.dump_config import intercept_dump_argument
from injector_common.targets import TargetProperty, Targets
from nmap.configuration.config_loader import ConfigLoader
from nmap.helpers.nmap_command_builder import NmapCommandBuilder
from nmap.helpers.nmap_output_parser import NmapOutputParser


class OpenAEVNmap:
    def __init__(self):
        self.config = OpenAEVConfigHelper.from_configuration_object(
            ConfigLoader().to_daemon_config()
        )
        intercept_dump_argument(self.config.get_config_obj())
        self.helper = OpenAEVInjectorHelper(
            self.config, open("nmap/img/icon-nmap.png", "rb")
        )
        self.signature_manager = SignatureManager(self.helper.api)

        self.current_inject_id = ""
        self.current_selector_key = ""
        self.current_selector_property = ""
        self.current_target_results = None
        self.current_expectation_types = []

    def update_current_elements(self, data: dict) -> None:
        self.current_inject_id = data["injection"]["inject_id"]

        content = data["injection"]["inject_content"]
        self.current_selector_key = content[TARGET_SELECTOR_KEY]
        self.current_selector_property = content[TARGET_PROPERTY_SELECTOR_KEY]

        self.current_target_results = Targets.extract_targets(
            self.current_selector_key, self.current_selector_property, data, self.helper
        )
        self.current_targets_meta = Targets.extract_target_meta(
            self.current_selector_key, self.current_selector_property, data, self.helper
        )

        self.current_expectation_types = [
            expectation.get("expectation_type")
            for expectation in content.get("expectations", [])
            if expectation.get("expectation_type")
        ]

    def get_targets(self) -> list:
        targets = self.current_target_results.targets
        # Handle empty targets as an error
        if not targets:
            message = f"No target identified for the property {TargetProperty[self.current_selector_property.upper()].value}"
            raise ValueError(message)

        return targets

    def nmap_execution(self, start: float, data: dict, targets: list) -> dict:
        contract_id = data["injection"]["inject_injector_contract"][
            "injector_contract_id"
        ]
        # Build Arguments to execute
        nmap_args = NmapCommandBuilder.build_args(contract_id, targets)

        self.helper.injector_logger.info(
            "Executing nmap with command: " + " ".join(nmap_args)
        )

        message = Targets.build_execution_message(
            selector_key=self.current_selector_key,
            data=data,
            command_args=nmap_args,
        )

        callback_data = {
            "execution_message": message,
            "execution_status": "INFO",
            "execution_duration": int(time.time() - start),
            "execution_action": "command_execution",
        }

        self.helper.api.inject.execution_callback(
            inject_id=self.current_inject_id,
            data=callback_data,
        )

        nmap_result = subprocess.run(nmap_args, check=True, capture_output=True)
        return NmapOutputParser.xmlparse(
            nmap_result.stdout, self.current_selector_key, self.current_target_results
        )

    def process_message(self, data: dict) -> None:
        start = time.time()
        # Notify API of reception and expected number of operations
        reception_data = {"tracking_total_count": 1}

        # setting the current elements
        self.update_current_elements(data)

        targets = self.get_targets()

        # create execution details object
        execution_details = ExecutionDetails()

        # generate execution signatures
        network_injector_configs = build_network_configs(targets)
        execution_signatures = self.signature_manager.build_execution_signatures(
            network_injector_configs
        )

        # sending execution reception
        self.helper.api.inject.execution_reception(
            inject_id=self.current_inject_id, data=reception_data
        )

        # Execute inject
        execution_result = None
        tool_error_info = None
        try:
            execution_result = self.nmap_execution(start, data, targets)
        except subprocess.CalledProcessError as err:
            execution_message = str(err.stderr.strip().decode())
            tool_error_info = {
                "exit_code": int(err.returncode),
            }
        except Exception as err:
            execution_message = str(err)
            tool_error_info = {
                "exit_code": 1,
            }
        else:
            execution_message = execution_result["message"]
        tool_output = {
            "error_info": tool_error_info,
        }

        # formatting callback data and tool_output
        callback_data = {
            "execution_message": execution_message,
            "execution_status": "ERROR" if tool_error_info else "SUCCESS",
            "execution_action": "complete",
        }
        if execution_result:
            callback_data["execution_output_structured"] = json.dumps(
                execution_result["outputs"]
            )

        # sending execution callback
        callback_data["execution_duration"] = int(time.time() - start)
        self.helper.api.inject.execution_callback(
            inject_id=self.current_inject_id, data=callback_data
        )

        # update post execution
        self.helper.injector_logger.info("post execution updates")
        self.signature_manager.post_execution_updates(
            execution_details, execution_signatures, tool_output
        )
        self.helper.injector_logger.info(execution_details)

        extra_signatures = ExtraSignatureData()
        if execution_result:
            outputs = execution_result.get("outputs", {})
            extra_data = {
                "ports_discovered": outputs.get("ports", []),
                "services_discovered": outputs.get("scan_results", []),
            }
            extra_signatures.detection = extra_data
            extra_signatures.prevention = extra_data

        # sending injection signatures per expectation type
        self.helper.injector_logger.info("build payload")
        payload = self.signature_manager.build_payload(
            execution_signatures=execution_signatures,
            targets_meta=self.current_targets_meta,
            expectation_types=self.current_expectation_types,
            extra_signatures=extra_signatures,
        )
        self.helper.injector_logger.info(payload)
        self.helper.injector_logger.info("send signatures")
        self.signature_manager.send_signatures(
            inject_id=self.current_inject_id,
            execution_details=execution_details,
            signatures=payload,
        )

    # Start the main loop
    def start(self):
        self.helper.listen(message_callback=self.process_message)


if __name__ == "__main__":
    openAEVNmap = OpenAEVNmap()
    openAEVNmap.start()
