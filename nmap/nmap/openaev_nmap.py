import json
import time
from typing import Dict

from pyoaev.helpers import OpenAEVConfigHelper, OpenAEVInjectorHelper

from injector_common.constants import TARGET_PROPERTY_SELECTOR_KEY, TARGET_SELECTOR_KEY
from injector_common.dump_config import intercept_dump_argument
from injector_common.targets import TargetProperty, Targets
from nmap.configuration.config_loader import ConfigLoader
from nmap.helpers.nmap_command_builder import NmapCommandBuilder
from nmap.helpers.nmap_output_parser import NmapOutputParser
from nmap.helpers.nmap_process import NmapProcess


class OpenAEVNmap:
    def __init__(self):
        self.config = OpenAEVConfigHelper.from_configuration_object(
            ConfigLoader().to_daemon_config()
        )
        intercept_dump_argument(self.config.get_config_obj())
        self.helper = OpenAEVInjectorHelper(
            self.config, open("nmap/img/icon-nmap.png", "rb")
        )

    def nmap_execution(self, start: float, data: Dict) -> Dict:
        inject_id = data["injection"]["inject_id"]
        contract_id = data["injection"]["inject_injector_contract"]["convertedContent"][
            "contract_id"
        ]
        content = data["injection"]["inject_content"]
        selector_key = content[TARGET_SELECTOR_KEY]
        selector_property = content[TARGET_PROPERTY_SELECTOR_KEY]

        target_results = Targets.extract_targets(
            selector_key, selector_property, data, self.helper
        )
        # Deduplicate targets
        targets = target_results.targets
        # Handle empty targets as an error
        if not targets:
            message = f"No target identified for the property {TargetProperty[selector_property.upper()].value}"
            raise ValueError(message)

        # Build Arguments to execute
        nmap_args = NmapCommandBuilder.build_args(contract_id, targets)

        self.helper.injector_logger.info(
            "Executing nmap with command: " + " ".join(nmap_args)
        )

        message = Targets.build_execution_message(
            selector_key=selector_key,
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
            inject_id=inject_id,
            data=callback_data,
        )

        nmap_result = NmapProcess.nmap_execute(nmap_args)
        jc = NmapProcess.js_execute(["jc", "--xml", "-p"], nmap_result)
        result = json.loads(jc.stdout.decode("utf-8").strip())

        return NmapOutputParser.parse(data, result, target_results)

    def process_message(self, data: Dict) -> None:
        start = time.time()
        inject_id = data["injection"]["inject_id"]
        # Notify API of reception and expected number of operations
        reception_data = {"tracking_total_count": 1}
        self.helper.api.inject.execution_reception(
            inject_id=inject_id, data=reception_data
        )
        # Execute inject
        try:
            execution_result = self.nmap_execution(start, data)
            callback_data = {
                "execution_message": execution_result["message"],
                "execution_output_structured": json.dumps(execution_result["outputs"]),
                "execution_status": "SUCCESS",
                "execution_duration": int(time.time() - start),
                "execution_action": "complete",
            }
            self.helper.api.inject.execution_callback(
                inject_id=inject_id, data=callback_data
            )
        except Exception as e:
            callback_data = {
                "execution_message": str(e),
                "execution_status": "ERROR",
                "execution_duration": int(time.time() - start),
                "execution_action": "complete",
            }
            self.helper.api.inject.execution_callback(
                inject_id=inject_id, data=callback_data
            )

    # Start the main loop
    def start(self):
        self.helper.listen(message_callback=self.process_message)


if __name__ == "__main__":
    openAEVNmap = OpenAEVNmap()
    openAEVNmap.start()
