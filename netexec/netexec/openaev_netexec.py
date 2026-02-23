import json
import os
import time
from importlib.resources import files
from typing import Dict

from pyoaev.helpers import OpenAEVConfigHelper, OpenAEVInjectorHelper

from injector_common.constants import TARGET_PROPERTY_SELECTOR_KEY, TARGET_SELECTOR_KEY
from injector_common.data_helpers import DataHelpers
from injector_common.dump_config import intercept_dump_argument
from injector_common.targets import TargetProperty, Targets
from netexec.configuration.config_loader import ConfigLoader
from netexec.contracts import parse_contract_id
from netexec.helpers.netexec_command_builder import (
    build_command,
    build_command_version,
    extract_data_base,
    extract_data_module,
    extract_data_option,
)
from netexec.helpers.netexec_output_parser import NetExecOutputParser
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

        self.parser = NetExecOutputParser()
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
        inject_id = DataHelpers.get_inject_id(data)
        inject_contract = DataHelpers.get_injector_contract_id(data)

        try:
            parsed = parse_contract_id(inject_contract)
        except ValueError:
            raise ValueError(
                f"Unsupported contract '{inject_contract}' for NetExec injector"
            )

        contract_family = parsed.family
        contract_identifier = parsed.identifier
        protocol = parsed.protocol
        content = DataHelpers.get_content(data)
        selector_key = content[TARGET_SELECTOR_KEY]
        selector_property = content[TARGET_PROPERTY_SELECTOR_KEY]

        target_results = Targets.extract_targets(
            selector_key, selector_property, data, self.helper
        )
        targets = target_results.targets
        if not targets:
            message = f"No target identified for the property {TargetProperty[selector_property.upper()].value}"
            raise ValueError(message)

        if parsed.family == "base":
            parsed_data = extract_data_base(content, protocol)
        elif parsed.family == "option":
            parsed_data = extract_data_option(content, protocol, parsed.identifier)
        elif parsed.family == "module":
            parsed_data = extract_data_module(content, protocol, parsed.identifier)
        else:
            raise ValueError(f"Unknown contract family: '{parsed.family}'")

        credentials = parsed_data.get("credentials") if parsed_data else None
        options = parsed_data.get("options") if parsed_data else None
        extra_args = parsed_data.get("extra_args") if parsed_data else None

        self.helper.injector_logger.info("Data: " + str(content))
        cmd = build_command(
            protocol=protocol,
            targets=targets,
            credentials=credentials,
            options=options,
            extra_args=extra_args,
        )

        callback_data = {
            "execution_message": Targets.build_execution_message(
                selector_key=selector_key,
                data=parsed_data,
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

        # Read and append temp output file for options that write to a file
        output_file = parsed_data.get("output_file") if parsed_data else None
        if output_file:
            try:
                with open(output_file, "r", encoding="utf-8", errors="replace") as f:
                    file_content = f.read()
                if file_content.strip():
                    stdout = stdout.rstrip("\n") + "\n" + file_content
            except FileNotFoundError:
                pass
            finally:
                try:
                    os.remove(output_file)
                except OSError:
                    pass

        parse_result = self.parser.parse(
            stdout,
            target_results.ip_to_asset_id_map,
            family=contract_family,
            identifier=contract_identifier,
        )
        return {
            "success": returncode == 0,
            "stdout": stdout,
            "stderr": stderr,
            "parsed": parse_result,
        }

    def process_message(self, data: Dict) -> None:
        start = time.time()
        inject_id = DataHelpers.get_inject_id(data)

        self.helper.api.inject.execution_reception(
            inject_id=inject_id,
            data={"tracking_total_count": 1},
        )

        try:
            result = self.execute(start, data)

            stdout = (result.get("stdout") or "").strip()
            stderr = (result.get("stderr") or "").strip()
            parsed = result.get("parsed")

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
                "execution_status": "SUCCESS" if result["success"] else "ERROR",
                "execution_duration": int(time.time() - start),
                "execution_action": "complete",
            }

            if parsed and parsed["outputs"]:
                callback_data["execution_output_structured"] = json.dumps(
                    parsed["outputs"]
                )

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
