import json
import multiprocessing
import os
import subprocess
import time
from typing import Dict

from pyobas.helpers import OpenBASConfigHelper, OpenBASInjectorHelper

from nuclei.helpers.nuclei_command_builder import NucleiCommandBuilder
from nuclei.helpers.nuclei_output_parser import NucleiOutputParser
from nuclei.helpers.nuclei_process import NucleiProcess
from nuclei.nuclei_contracts.external_contracts import ExternalContractsScheduler
from nuclei.nuclei_contracts.nuclei_contracts import NucleiContracts


class OpenBASNuclei:
    def __init__(self):
        print(os.getenv("PATH"))
        self.config = OpenBASConfigHelper(
            __file__,
            {
                "openbas_url": {"env": "OPENBAS_URL", "file_path": ["openbas", "url"]},
                "openbas_token": {
                    "env": "OPENBAS_TOKEN",
                    "file_path": ["openbas", "token"],
                },
                "injector_id": {"env": "INJECTOR_ID", "file_path": ["injector", "id"]},
                "injector_name": {
                    "env": "INJECTOR_NAME",
                    "file_path": ["injector", "name"],
                },
                "injector_type": {
                    "env": "INJECTOR_TYPE",
                    "file_path": ["injector", "type"],
                    "default": "openbas_nuclei",
                },
                "injector_contracts": {
                    "data": NucleiContracts.build_static_contracts()
                },
                "injector_external_contracts_maintenance_schedule_seconds": {
                    "env": "INJECTOR_EXTERNAL_CONTRACTS_MAINTENANCE_SCHEDULE_SECONDS",
                    "file_path": [
                        "injector",
                        "external_contracts_maintenance_schedule_seconds",
                    ],
                    "default": 86400,
                    "is_number": True,
                },
                "injector_log_level": {
                    "env": "INJECTOR_LOG_LEVEL",
                    "file_path": ["injector", "log_level"],
                    "default": "warn",
                },
            },
        )
        self.helper = OpenBASInjectorHelper(
            self.config, open("nuclei/img/nuclei.jpg", "rb")
        )

        if not self._check_nuclei_installed():
            raise RuntimeError(
                "Nuclei is not installed or is not accessible from your PATH."
            )
        self.command_builder = NucleiCommandBuilder()
        self.parser = NucleiOutputParser()

    def nuclei_execution(self, start: float, data: Dict) -> Dict:
        inject_id = data["injection"]["inject_id"]
        contract_id = data["injection"]["inject_injector_contract"]["convertedContent"][
            "contract_id"
        ]
        content = data["injection"]["inject_content"]

        target_results = NucleiContracts.extract_targets(data)
        nuclei_args = self.command_builder.build_args(
            contract_id, content, target_results.targets
        )
        input_data = "\n".join(target_results.targets).encode("utf-8")

        self.helper.injector_logger.info(
            "Executing nuclei with: " + " ".join(nuclei_args)
        )
        self.helper.api.inject.execution_callback(
            inject_id=inject_id,
            data={
                "execution_message": " ".join(nuclei_args),
                "execution_status": "INFO",
                "execution_duration": int(time.time() - start),
                "execution_action": "command_execution",
            },
        )

        result = NucleiProcess.nuclei_execute(nuclei_args, input_data)
        return self.parser.parse(
            result.stdout.decode("utf-8"), target_results.ip_to_asset_id_map
        )

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
            result = self.nuclei_execution(start, data)
            callback_data = {
                "execution_message": result["message"],
                "execution_output_structured": json.dumps(result["outputs"]),
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

    def _check_nuclei_installed(self):
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
    OpenBASNuclei().start()
