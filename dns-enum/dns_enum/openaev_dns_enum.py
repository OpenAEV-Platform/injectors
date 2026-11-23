import json
import os
import subprocess
import tempfile
import time
from typing import Dict, List, Optional, Tuple, Union

from dns_enum.configuration.config_loader import ConfigLoader
from dns_enum.contracts.dns_enum_constants import HOSTNAMES_FIELD
from dns_enum.helpers.dns_enum_command_builder import DnsEnumCommandBuilder
from dns_enum.helpers.dns_enum_output_parser import DnsEnumOutputParser
from dns_enum.helpers.endpoint_importer import EndpointImporter
from dns_enum.models.data import MessageData
from pyoaev.helpers import OpenAEVConfigHelper, OpenAEVInjectorHelper
from pyoaev.signatures import SignatureManager
from pyoaev.signatures.models import (
    ExecutionDetails,
    ExtraSignatureData,
    build_network_configs,
)

from injector_common.dump_config import intercept_dump_argument


def _write_lines(directory: str, name: str, lines: List[str]) -> str:
    path = os.path.join(directory, name)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")
    return path


def _decode(output: Optional[Union[bytes, str]]) -> str:
    if output is None:
        return ""
    if isinstance(output, bytes):
        return output.decode("utf-8", errors="replace")
    return output


class OpenAEVDnsEnum:
    def __init__(self):
        self.config = OpenAEVConfigHelper.from_configuration_object(
            ConfigLoader().to_daemon_config()
        )
        intercept_dump_argument(self.config.get_config_obj())
        self.helper = OpenAEVInjectorHelper(
            self.config, open("dns_enum/img/icon-dns-enum.png", "rb")
        )
        self.signature_manager = SignatureManager(self.helper.api)

    def _run(self, args: List[str], timeout: float) -> Tuple[str, bool]:
        """Run one tool; on its deadline, keep what it printed so far.

        Returns (stdout, timed_out). subprocess.run kills the process on
        TimeoutExpired and attaches the output collected until then.
        """
        self.helper.injector_logger.info("Executing: " + " ".join(args))
        try:
            result = subprocess.run(
                args, check=True, capture_output=True, timeout=max(1, timeout)
            )
        except subprocess.TimeoutExpired as err:
            self.helper.injector_logger.warning(
                f"{args[0]} reached its deadline; keeping its partial output"
            )
            return _decode(err.stdout), True
        return _decode(result.stdout), False

    def _callback(self, inject_id: str, start: float, message: str) -> None:
        self.helper.api.inject.execution_callback(
            inject_id=inject_id,
            data={
                "execution_message": message,
                "execution_status": "INFO",
                "execution_duration": int(time.time() - start),
                "execution_action": "command_execution",
            },
        )

    def enumerate(self, start: float, msg_data: MessageData) -> Dict:
        """Collect candidates (roots, passive sources, wordlist), resolve them with dnsx."""
        deadline = start + msg_data.timeout
        candidates: List[str] = list(msg_data.domains)
        timed_out = False
        with tempfile.TemporaryDirectory() as workdir:
            if msg_data.passive_sources:
                domains_file = _write_lines(workdir, "domains.txt", msg_data.domains)
                # Passive collection gets half of the budget at most, so dnsx
                # always keeps the other half to resolve the candidates.
                passive_budget = DnsEnumCommandBuilder.passive_budget(msg_data.timeout)
                args = DnsEnumCommandBuilder.subfinder_args(
                    domains_file, msg_data.rate_limit, passive_budget
                )
                self._callback(msg_data.inject_id, start, " ".join(args))
                passive, _ = self._run(
                    args, min(passive_budget, deadline - time.time())
                )
                for line in passive.splitlines():
                    host = line.strip().lower().rstrip(".")
                    if (
                        host
                        and host not in candidates
                        and DnsEnumOutputParser.in_scope(host, msg_data.domains)
                    ):
                        candidates.append(host)
            if msg_data.brute_force:
                for host in DnsEnumCommandBuilder.brute_force_candidates(
                    msg_data.domains, msg_data.wordlist
                ):
                    if host not in candidates:
                        candidates.append(host)
            hosts_file = _write_lines(workdir, "hosts.txt", candidates)
            args = DnsEnumCommandBuilder.dnsx_args(
                hosts_file, msg_data.record_types, msg_data.rate_limit
            )
            self._callback(
                msg_data.inject_id,
                start,
                f"{' '.join(args)} ({len(candidates)} candidate hosts)",
            )
            resolved, timed_out = self._run(args, deadline - time.time())
        hosts = DnsEnumOutputParser.parse_hosts(resolved, msg_data.domains)
        return {
            "hosts": hosts,
            "outputs": DnsEnumOutputParser.build_outputs(hosts, resolved),
            "candidates": len(candidates),
            "timed_out": timed_out,
        }

    def _report_pre_execution_failure(
        self, data: dict, start: float, err: Exception
    ) -> None:
        injection = data.get("injection") if isinstance(data, dict) else None
        inject_id = injection.get("inject_id") if isinstance(injection, dict) else None
        if not inject_id:
            self.helper.injector_logger.error(
                "dns-enum pre-execution failure with unresolvable inject id: "
                + str(err)
            )
            return
        self.helper.injector_logger.error("dns-enum pre-execution failure: " + str(err))
        self.helper.api.inject.execution_reception(
            inject_id=inject_id, data={"tracking_total_count": 1}
        )
        self.helper.api.inject.execution_callback(
            inject_id=inject_id,
            data={
                "execution_message": "Pre-execution failure: " + str(err),
                "execution_status": "ERROR",
                "execution_duration": int(time.time() - start),
                "execution_action": "complete",
            },
        )

    def process_message(self, data: dict) -> None:
        start = time.time()
        try:
            msg_data = MessageData(data)
            execution_signatures = self.signature_manager.build_execution_signatures(
                build_network_configs(msg_data.domains)
            )
        except Exception as err:
            self._report_pre_execution_failure(data, start, err)
            return

        execution_details = ExecutionDetails()
        self.helper.api.inject.execution_reception(
            inject_id=msg_data.inject_id, data={"tracking_total_count": 1}
        )

        result = None
        tool_error_info = None
        try:
            result = self.enumerate(start, msg_data)
        except subprocess.CalledProcessError as err:
            stderr = err.stderr.decode("utf-8", errors="replace") if err.stderr else ""
            execution_message = stderr.strip() or str(err)
            tool_error_info = {"exit_code": int(err.returncode)}
        except subprocess.TimeoutExpired:
            execution_message = f"Enumeration timed out after {msg_data.timeout} s"
            tool_error_info = {"exit_code": 124}
        except Exception as err:
            execution_message = str(err)
            tool_error_info = {"exit_code": 1}
        else:
            execution_message = (
                f"{len(result['hosts'])} hosts resolved out of "
                f"{result['candidates']} candidates"
            )
            if result["timed_out"]:
                execution_message += (
                    f" (resolution stopped at the {msg_data.timeout} s deadline:"
                    " partial results)"
                )
                if not result["hosts"]:
                    tool_error_info = {"exit_code": 124}
            if msg_data.create_endpoints:
                imported = EndpointImporter(
                    self.helper.api, self.helper.injector_logger
                ).import_hosts(
                    result["hosts"],
                    msg_data.endpoint_tag,
                    msg_data.asset_group_id,
                    msg_data.classify_assets,
                )
                execution_message += (
                    f"; {len(imported['asset_ids'])} endpoints created or updated"
                    f" (tag {msg_data.endpoint_tag})"
                )
                if imported.get("web_applications"):
                    execution_message += (
                        f"; {imported['web_applications']} classified as web"
                        " applications"
                    )
                if imported.get("servers"):
                    execution_message += (
                        f"; {imported['servers']} classified as servers"
                    )
                if imported.get("attached"):
                    execution_message += (
                        "; attached to an existing asset of the same address"
                        f" (left unchanged): {', '.join(imported['attached'])}"
                    )
                if imported.get("skipped"):
                    execution_message += (
                        "; not imported, their address could not be checked"
                        f" against existing assets: {', '.join(imported['skipped'])}"
                    )
                if imported.get("lookup_error"):
                    execution_message += (
                        "; existing assets unreadable, imported without"
                        f" classification: {imported['lookup_error']}"
                    )
                if imported["failed"]:
                    execution_message += (
                        f"; endpoint import failed for {', '.join(imported['failed'])}"
                    )
                if imported["asset_group_error"]:
                    execution_message += (
                        f"; asset group update failed: {imported['asset_group_error']}"
                    )
            else:
                execution_message += "; no endpoint created (option off)"

        callback_data = {
            "execution_message": execution_message,
            "execution_status": "ERROR" if tool_error_info else "SUCCESS",
            "execution_action": "complete",
            "execution_duration": int(time.time() - start),
        }
        if result:
            callback_data["execution_output_structured"] = json.dumps(result["outputs"])
        self.helper.api.inject.execution_callback(
            inject_id=msg_data.inject_id, data=callback_data
        )

        self.signature_manager.post_execution_updates(
            execution_details, execution_signatures, {"error_info": tool_error_info}
        )
        extra_signatures = ExtraSignatureData()
        if result:
            extra_data = {
                "hosts_discovered": result["outputs"].get(HOSTNAMES_FIELD, [])
            }
            extra_signatures.detection = extra_data
            extra_signatures.prevention = extra_data
        payload = self.signature_manager.build_payload(
            execution_signatures=execution_signatures,
            targets_meta=[],
            expectation_types=msg_data.expectation_types,
            extra_signatures=extra_signatures,
        )
        self.signature_manager.send_signatures(
            inject_id=msg_data.inject_id,
            execution_details=execution_details,
            signatures=payload,
        )

    def start(self):
        self.helper.listen(message_callback=self.process_message)


if __name__ == "__main__":
    OpenAEVDnsEnum().start()
