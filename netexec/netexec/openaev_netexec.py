import time
from importlib.resources import files
from typing import Dict

from pyoaev.helpers import OpenAEVConfigHelper, OpenAEVInjectorHelper

from injector_common.constants import TARGET_PROPERTY_SELECTOR_KEY, TARGET_SELECTOR_KEY
from injector_common.data_helpers import DataHelpers
from injector_common.dump_config import intercept_dump_argument
from injector_common.targets import TargetProperty, Targets
from netexec.configuration.config_loader import ConfigLoader
from netexec.contracts_netexec import (
    CONTRACT_ID_SMB_AUTH,
)
from netexec.helpers.netexec_command_builder import (
    build_command_smb,
    build_command_version,
    extract_data,
)
from netexec.helpers.netexec_process import execute_netexec


class OpenAEVNetExecInjector:
    def __init__(self):
        self.config = OpenAEVConfigHelper.from_configuration_object(
            ConfigLoader().to_daemon_config()
        )
        intercept_dump_argument(self.config.get_config_obj())
        icon_path = files("netexec").joinpath("img/icon-netexec.png")
        with icon_path.open("rb") as icon_file:
            icon_bytes = icon_file.read()
        print(self.config)
        self.helper = OpenAEVInjectorHelper(self.config, icon_bytes)

        self._check_netexec_version()

    def _check_netexec_version(self):
        cmd = build_command_version()
        stdout, stderr, returncode = execute_netexec(cmd)
        if returncode != 0:
            self.helper.injector_logger.warning(
                f"Unable to determine NetExec version: {stderr}"
            )
            return
        self.helper.injector_logger.info("NetExec version: " + stdout.strip())

    def execute(self, start: float, data: Dict) -> Dict:
        # Contract execution
        inject_id = DataHelpers.get_inject_id(data)
        inject_contract = DataHelpers.get_injector_contract_id(data)

        available_contracts = {
            CONTRACT_ID_SMB_AUTH: build_command_smb,
        }

        if inject_contract not in available_contracts:
            raise ValueError(
                f"Unsupported contract '{inject_contract}' for NetExec injector"
            )

        content = DataHelpers.get_content(data)
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
        data = extract_data(content)

        credentials = data.get("credentials") if data else None
        options = data.get("options") if data else None
        self.helper.injector_logger.info("Data: " + str(content))
        cmd = build_command_smb(
            targets=targets,
            credentials=credentials,
            options=options,
        )

        callback_data = {
            "execution_message": Targets.build_execution_message(
                selector_key=selector_key,
                data=data,
                command_args=cmd,
            ),
            "execution_status": "INFO",
            "execution_duration": int(time.time() - start),
            "execution_action": "command_execution",
        }

        self.helper.api.inject.execution_callback(
            inject_id=inject_id,
            data=callback_data,
        )

        stdout, stderr, returncode = execute_netexec(cmd)
        return {
            "success": returncode == 0,
            "stdout": stdout,
            "stderr": stderr,
        }

    def process_message(self, data: Dict) -> None:
        start = time.time()
        inject_id = DataHelpers.get_inject_id(data)

        # Notify OpenAEV that execution started
        self.helper.api.inject.execution_reception(
            inject_id=inject_id,
            data={"tracking_total_count": 1},
        )

        try:
            result = self.execute(start, data)

            stdout = (result.get("stdout") or "").strip()
            stderr = (result.get("stderr") or "").strip()

            if result["success"]:
                if stdout:
                    execution_message = f"NetExec succeeded:\n{stdout}"
                else:
                    execution_message = "NetExec succeeded: no results found"
            else:
                execution_message = (
                    f"NetExec failed:\n{stderr or stdout or 'No error output'}"
                )

            callback_data = {
                "execution_message": execution_message,
                # "execution_output_structured": "",
                "execution_status": "SUCCESS" if result["success"] else "ERROR",
                "execution_duration": int(time.time() - start),
                "execution_action": "complete",
            }

            self.helper.api.inject.execution_callback(
                inject_id=inject_id,
                data=callback_data,
            )

        except Exception as e:
            callback_data = {
                "execution_message": str(e),
                "execution_status": "ERROR",
                "execution_duration": int(time.time() - start),
                "execution_action": "complete",
            }

            self.helper.api.inject.execution_callback(
                inject_id=inject_id,
                data=callback_data,
            )

    def start(self):
        self.helper.listen(message_callback=self.process_message)


if __name__ == "__main__":
    injector = OpenAEVNetExecInjector()
    injector.start()
