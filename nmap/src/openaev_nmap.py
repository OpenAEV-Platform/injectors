import json
import time
from typing import Dict

from common.constants import TARGET_SELECTOR_KEY
from common.targets import Targets
from pyoaev.helpers import OpenAEVConfigHelper, OpenAEVInjectorHelper

from contracts.nmap_contracts import NmapContracts
from helpers.nmap_command_builder import NmapCommandBuilder
from helpers.nmap_output_parser import NmapOutputParser
from helpers.nmap_process import NmapProcess


class OpenAEVNmap:
    def __init__(self):
        self.config = OpenAEVConfigHelper(
            __file__,
            {
                # API information
                "openaev_url": {"env": "OPENAEV_URL", "file_path": ["openaev", "url"]},
                "openaev_token": {
                    "env": "OPENAEV_TOKEN",
                    "file_path": ["openaev", "token"],
                },
                # Config information
                "injector_id": {"env": "INJECTOR_ID", "file_path": ["injector", "id"]},
                "injector_name": {
                    "env": "INJECTOR_NAME",
                    "file_path": ["injector", "name"],
                },
                "injector_type": {
                    "env": "INJECTOR_TYPE",
                    "file_path": ["injector", "type"],
                    "default": "openaev_nmap",
                },
                "injector_contracts": {"data": NmapContracts.build_contract()},
            },
        )
        self.helper = OpenAEVInjectorHelper(
            self.config, open("img/icon-nmap.png", "rb")
        )

    def nmap_execution(self, start: float, data: Dict) -> Dict:
        inject_id = data["injection"]["inject_id"]
        contract_id = data["injection"]["inject_injector_contract"]["convertedContent"][
            "contract_id"
        ]
        selector_key = data["injection"]["inject_content"][TARGET_SELECTOR_KEY]

        target_results = Targets.extract_targets(selector_key, data, self.helper)
        asset_list = list(target_results.ip_to_asset_id_map.values())
        # Deduplicate targets
        unique_targets = list(dict.fromkeys(target_results.targets))
        # Build Arguments to execute
        nmap_args = NmapCommandBuilder.build_args(contract_id, unique_targets)

        self.helper.injector_logger.info(
            "Executing nmap with command: " + " ".join(nmap_args)
        )

        callback_data = {
            "execution_message": Targets.build_execution_message(
                selector_key=selector_key,
                data=data,
                command_args=nmap_args,
            ),
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

        return NmapOutputParser.parse(data, result, asset_list)

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
