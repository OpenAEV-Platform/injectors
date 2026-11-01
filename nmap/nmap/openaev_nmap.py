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

from injector_common.dump_config import intercept_dump_argument
from injector_common.targets import Targets
from injector_common.traces import send_per_target_traces
from nmap.configuration.config_loader import ConfigLoader
from nmap.helpers.nmap_command_builder import NmapCommandBuilder
from nmap.helpers.nmap_output_parser import NmapOutputParser
from nmap.models.data import MessageData


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

    def nmap_execution(self, start: float, msg_data: MessageData) -> dict:
        # Build Arguments to execute
        nmap_args = NmapCommandBuilder.build_args(
            msg_data.contract_id,
            msg_data.get_targets(),
        )

        self.helper.injector_logger.info(
            "Executing nmap with command: " + " ".join(nmap_args)
        )

        message = Targets.build_execution_message(
            selector_key=msg_data.selector_key,
            data=msg_data.raw_data,
            command_args=nmap_args,
        )

        callback_data = {
            "execution_message": message,
            "execution_status": "INFO",
            "execution_duration": int(time.time() - start),
            "execution_action": "command_execution",
        }

        self.helper.api.inject.execution_callback(
            inject_id=msg_data.inject_id,
            data=callback_data,
        )

        # Per-target traces so each asset-backed endpoint's result view shows the
        # scan reached it; the batched scan only sends a global callback otherwise.
        send_per_target_traces(
            self.helper,
            msg_data.inject_id,
            msg_data.target_results.ip_to_asset_id_map,
            label="nmap scan",
            start=start,
        )

        nmap_result = subprocess.run(nmap_args, check=True, capture_output=True)
        return NmapOutputParser.xmlparse(
            nmap_result.stdout, msg_data.selector_key, msg_data.target_results
        )

    def _report_pre_execution_failure(
        self, data: dict, start: float, err: Exception
    ) -> None:
        # Per-inject errors must never escape process_message: even when the
        # inject fails before nmap runs, the platform must still get a terminal
        # result. Resolve the inject id straight from the raw payload since a
        # MessageData failure means msg_data is not available. Do it defensively:
        # this helper runs precisely when the payload could not be parsed, so the
        # inject id may itself be missing - in that case we cannot address a
        # terminal callback anywhere, so log and return instead of raising (which
        # would re-raise out of process_message, the opposite of the guard).
        injection = data.get("injection") if isinstance(data, dict) else None
        inject_id = injection.get("inject_id") if isinstance(injection, dict) else None
        if not inject_id:
            self.helper.injector_logger.error(
                "nmap pre-execution failure with unresolvable inject id: " + str(err)
            )
            return
        self.helper.injector_logger.error("nmap pre-execution failure: " + str(err))
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

        # unpacking the message, resolving targets and building the pre-execution
        # signatures can all raise (invalid payload, no targets, signature setup);
        # guard them so a failure is reported instead of propagating out.
        try:
            msg_data = MessageData(data, self.helper)
            targets = msg_data.get_targets()
            network_injector_configs = build_network_configs(targets)
            execution_signatures = self.signature_manager.build_execution_signatures(
                network_injector_configs
            )
        except Exception as err:
            self._report_pre_execution_failure(data, start, err)
            return

        # create execution details object
        execution_details = ExecutionDetails()

        # Notify API of reception and expected number of operations
        reception_data = {"tracking_total_count": 1}

        # sending execution reception
        self.helper.api.inject.execution_reception(
            inject_id=msg_data.inject_id, data=reception_data
        )

        # Execute inject
        execution_result = None
        tool_error_info = None
        try:
            execution_result = self.nmap_execution(start, msg_data)
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
            inject_id=msg_data.inject_id, data=callback_data
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
            targets_meta=msg_data.targets_meta,
            expectation_types=msg_data.expectation_types,
            extra_signatures=extra_signatures,
        )
        self.helper.injector_logger.info(payload)
        self.helper.injector_logger.info("send signatures")
        self.signature_manager.send_signatures(
            inject_id=msg_data.inject_id,
            execution_details=execution_details,
            signatures=payload,
        )

    # Start the main loop
    def start(self):
        self.helper.listen(message_callback=self.process_message)


if __name__ == "__main__":
    openAEVNmap = OpenAEVNmap()
    openAEVNmap.start()
