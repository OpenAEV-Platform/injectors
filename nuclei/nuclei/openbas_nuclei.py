import json
import subprocess
import time
from typing import Dict

from pyobas.helpers import OpenBASConfigHelper, OpenBASInjectorHelper

from nuclei.helpers.nuclei_command_builder import NucleiCommandBuilder
from nuclei.helpers.nuclei_output_parser import NucleiOutputParser
from nuclei.helpers.nuclei_process import NucleiProcess
from nuclei.nuclei_contracts.nuclei_contracts import NucleiContracts


class OpenBASNuclei:
    def __init__(self):
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
                "injector_contracts": {"data": NucleiContracts.build_contracts()},
            },
        )
        self.helper = OpenBASInjectorHelper(
            self.config, open("img/nuclei.jpg", "rb")
        )

        if not self._check_nuclei_installed():
            raise RuntimeError(
                "Nuclei is not installed or is not accessible from your PATH."
            )
        self._update_templates()

        self.command_builder = NucleiCommandBuilder()
        self.parser = NucleiOutputParser()

    def nuclei_execution(self, start: float, data: Dict) -> Dict:
        inject_id = data["injection"]["inject_id"]
        contract_id = data["injection"]["inject_injector_contract"]["convertedContent"][
            "contract_id"
        ]
        content = data["injection"]["inject_content"]

        targets = NucleiContracts.extract_targets(data)
        nuclei_args = self.command_builder.build_args(contract_id, content, targets)
        input_data = "\n".join(targets).encode("utf-8")

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
        return self.parser.parse(result.stdout.decode("utf-8"))

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

    def _update_templates(self):
        self.helper.injector_logger.info("Updating templates...")
        try:
            NucleiProcess.nuclei_update_templates()
            self.helper.injector_logger.info("Templates updated successfully.")
        except subprocess.CalledProcessError as e:
            self.helper.injector_logger.error(f"Template update failed: {e}")

    def start(self):
        self.helper.listen(message_callback=self.process_message)


if __name__ == "__main__":
    OpenBASNuclei().start()
