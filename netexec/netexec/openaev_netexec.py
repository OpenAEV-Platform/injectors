import json
import os
import time
from importlib.resources import files

from pyoaev.helpers import OpenAEVConfigHelper, OpenAEVInjectorHelper
from pyoaev.signatures import SignatureManager
from pyoaev.signatures.models import ExtraSignatureData, build_network_configs

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

_SENSITIVE_KEYS = {"password", "hash", "key_file", "username", "domain"}


def _redact_content(content: dict) -> dict:
    """Return a shallow copy with sensitive values masked."""
    return {k: "***" if k in _SENSITIVE_KEYS else v for k, v in content.items()}


_CREDENTIAL_FLAGS = {"-u", "-p", "-H", "-d", "--key-file"}


def _redact_cmd(cmd: list[str]) -> list[str]:
    """Return a copy of cmd with credential values replaced by '***'."""
    redacted = []
    skip_next = False
    for arg in cmd:
        if skip_next:
            redacted.append("***")
            skip_next = False
        elif arg in _CREDENTIAL_FLAGS:
            redacted.append(arg)
            skip_next = True
        else:
            redacted.append(arg)
    return redacted


class OpenAEVNetExecInjector:
    def __init__(self):
        self.config = OpenAEVConfigHelper.from_configuration_object(
            ConfigLoader().to_daemon_config()
        )
        intercept_dump_argument(self.config.get_config_obj())
        icon_path = files("netexec").joinpath("img/icon-netexec.png")
        with icon_path.open("rb") as icon_file:
            icon_bytes = icon_file.read()
        self.helper = OpenAEVInjectorHelper(self.config, icon_bytes)

        self.parser = NetExecOutputParser()
        self.sm = SignatureManager(self.helper.api)
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

    def execute(self, start: float, data: dict) -> dict:
        inject_id = DataHelpers.get_inject_id(data)
        inject_contract = DataHelpers.get_injector_contract_id(data)

        try:
            parsed = parse_contract_id(inject_contract)
        except ValueError as err:
            raise ValueError(
                f"Unsupported contract '{inject_contract}' for NetExec injector"
            ) from err

        contract_family = parsed.family
        contract_identifier = parsed.identifier
        protocol = parsed.protocol
        content = DataHelpers.get_content(data)
        selector_key = content[TARGET_SELECTOR_KEY]
        selector_property = content[TARGET_PROPERTY_SELECTOR_KEY]

        expectations = content.get("expectations", [])
        expectation_types = list(
            {
                exp.get("expectation_type", "").upper()
                for exp in expectations
                if exp.get("expectation_type")
            }
        ) or ["DETECTION"]

        target_results = Targets.extract_targets(
            selector_key, selector_property, data, self.helper
        )
        targets = target_results.targets
        if not targets:
            message = f"No target identified for the property {TargetProperty[selector_property.upper()].value}"
            raise ValueError(message)

        if contract_family == "base":
            parsed_data = extract_data_base(content, protocol)
        elif contract_family == "option":
            parsed_data = extract_data_option(content, protocol, contract_identifier)
        elif contract_family == "module":
            parsed_data = extract_data_module(content, protocol, contract_identifier)
        else:
            raise ValueError(f"Unknown contract family: '{contract_family}'")

        credentials = parsed_data.get("credentials") if parsed_data else None
        options = parsed_data.get("options") if parsed_data else None
        extra_args = parsed_data.get("extra_args") if parsed_data else None

        self.helper.injector_logger.info("Data: " + str(_redact_content(content)))
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
                command_args=_redact_cmd(cmd),
            ),
            "execution_status": "INFO",
            "execution_duration": int(time.time() - start),
            "execution_action": "command_execution",
        }

        self.helper.api.inject.execution_callback(
            inject_id=inject_id,
            data=callback_data,
        )

        output_file = parsed_data.get("output_file") if parsed_data else None
        pre_sigs = self._compile_pre_signatures(targets)
        try:
            stdout, stderr, returncode = execute_netexec(cmd)

            # Read and append temp output file for options that write to a file
            if output_file:
                try:
                    with open(
                        output_file, "r", encoding="utf-8", errors="replace"
                    ) as f:
                        file_content = f.read()
                    if file_content.strip():
                        stdout = stdout.rstrip("\n") + "\n" + file_content
                except FileNotFoundError:
                    pass
        except Exception:
            pass
        finally:
            if output_file:
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
            "stderr_raw": stderr,
            "returncode": returncode,
            "parsed": parse_result,
            "targets": targets,
            "pre_sigs": pre_sigs,
            "protocol": protocol,
            "expectation_types": expectation_types,
        }

    def _compile_pre_signatures(self, targets: list[str]) -> dict | list[dict]:
        """Compile pre-execution signatures (captures start_time)."""
        configs = build_network_configs(targets)
        return self.sm.compile_pre_execution_signatures(config=configs)

    def _send_signatures(
        self,
        inject_id: str,
        pre_sigs: dict | list[dict],
        returncode: int,
        protocol: str,
        expectation_types: list[str],
    ) -> None:
        """Compile post-execution signatures and send the payload."""
        tool_output: dict = {}
        if returncode != 0:
            tool_output["error_info"] = {"exit_code": returncode}
        post_sigs = self.sm.compile_post_execution_signatures(pre_sigs, tool_output)

        extra_data = {
            "protocols_tested": [protocol],
            "protocols_succeeded": [protocol] if returncode == 0 else [],
        }
        extra_signatures = ExtraSignatureData(
            detection=extra_data,
            prevention=extra_data,
        )

        payload = self.sm.build_payload(
            post_sigs if isinstance(post_sigs, list) else [post_sigs],
            expectation_types=expectation_types,
            extra_signatures=extra_signatures,
        )
        self.sm.send_signatures(
            inject_id=inject_id,
            phase="execution_complete",
            signatures=payload,
        )

    def process_message(self, data: dict) -> None:
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
            targets = result.get("targets", [])
            pre_sigs = result.get("pre_sigs")
            returncode = result.get("returncode", 0 if result["success"] else 1)

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

            callback_data["execution_output_structured"] = json.dumps(
                parsed["outputs"] if parsed and parsed.get("outputs") else {}
            )

            self.helper.api.inject.execution_callback(
                inject_id=inject_id,
                data=callback_data,
            )

            if targets:
                protocol = result.get("protocol", "")
                expectation_types = result.get("expectation_types", ["DETECTION"])
                self._send_signatures(
                    inject_id,
                    pre_sigs,
                    returncode,
                    protocol,
                    expectation_types,
                )

        except Exception as e:
            self.helper.injector_logger.error(
                "Execution failed for inject %s: %s", inject_id, e
            )
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
