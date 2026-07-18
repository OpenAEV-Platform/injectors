import json
import subprocess
import time
from typing import Dict

from pyoaev.helpers import OpenAEVConfigHelper, OpenAEVInjectorHelper
from pyoaev.signatures import (
    ExtraSignatureData,
    SignatureManager,
    build_network_configs,
)
from pyoaev.signatures.models import ExecutionDetails

from injector_common.dump_config import intercept_dump_argument
from injector_common.targets import Targets
from nuclei.configuration.config_loader import ConfigLoader
from nuclei.helpers.nuclei_command_builder import NucleiCommandBuilder
from nuclei.helpers.nuclei_output_parser import NucleiOutputParser
from nuclei.helpers.nuclei_process import NucleiProcess
from nuclei.models.data import MessageData
from nuclei.nuclei_contracts.external_contracts import ExternalContractsScheduler


class OpenAEVNuclei:
    def __init__(self):
        self.config_loader = ConfigLoader()
        self.config = OpenAEVConfigHelper.from_configuration_object(
            self.config_loader.to_daemon_config()
        )
        intercept_dump_argument(self.config.get_config_obj())
        self.helper = OpenAEVInjectorHelper(
            self.config, open("nuclei/img/nuclei.jpg", "rb")
        )

        if not self._check_nuclei_installed():
            raise RuntimeError(
                "Nuclei is not installed or is not accessible from your PATH."
            )
        self.parser = NucleiOutputParser()

    def nuclei_execution(
        self,
        start: float,
        msg_data: MessageData,
    ) -> Dict:
        targets = msg_data.get_targets()
        # Nuclei Args Builder
        nuclei_builder = NucleiCommandBuilder(
            nuclei_configs=self.config_loader.nuclei,
            contract_id=msg_data.contract_id,
            content=msg_data.inject_content,
            targets=targets,
        )
        nuclei_args = nuclei_builder.build()

        self.helper.injector_logger.info(
            "Executing nuclei with: " + " ".join(nuclei_args)
        )

        callback_data = {
            "execution_message": Targets.build_execution_message(
                selector_key=msg_data.selector_key,
                data=msg_data.raw_data,
                command_args=nuclei_args,
            ),
            "execution_status": "INFO",
            "execution_duration": int(time.time() - start),
            "execution_action": "command_execution",
        }

        self.helper.api.inject.execution_callback(
            inject_id=msg_data.inject_id,
            data=callback_data,
        )

        input_data = ("\n".join(targets) + "\n").encode("utf-8")
        result = NucleiProcess.nuclei_execute(nuclei_args, input_data)

        return self.parser.parse(
            result.stdout.decode("utf-8"), msg_data.target_results.ip_to_asset_id_map
        )

    def _report_pre_execution_failure(
        self, data: Dict, start: float, err: Exception
    ) -> None:
        # Per-inject errors must never escape process_message: even when the
        # inject fails before nuclei runs, the platform must still get a terminal
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
                "nuclei pre-execution failure with unresolvable inject id: " + str(err)
            )
            return
        self.helper.injector_logger.error("nuclei pre-execution failure: " + str(err))
        self.helper.api.inject.execution_reception(
            inject_id=inject_id, data={"tracking_total_count": 1}
        )
        self.helper.api.inject.execution_callback(
            inject_id=inject_id,
            data={
                "execution_message": f"Pre-execution failure: {err}",
                "execution_status": "ERROR",
                "execution_duration": int(time.time() - start),
                "execution_action": "complete",
            },
        )

    def process_message(self, data: Dict) -> None:
        start = time.time()

        # unpacking the message can raise (invalid payload, no targets); guard it
        # so a failure is reported instead of propagating out of process_message.
        try:
            msg_data = MessageData(data, self.helper)
        except Exception as err:
            self._report_pre_execution_failure(data, start, err)
            return

        # Notify API of reception and expected number of operations
        reception_data = {"tracking_total_count": 1}
        self.helper.api.inject.execution_reception(
            inject_id=msg_data.inject_id, data=reception_data
        )

        # Injector Signature Manager
        signature_manager = SignatureManager(self.helper.api)

        execution_details = ExecutionDetails()

        pre_execute_fail_flag = False
        pre_execute_fail_message = ""

        try:
            configs = build_network_configs(msg_data.get_targets())
        except Exception as e:
            # This guards both target resolution (msg_data.get_targets, which
            # raises a user-facing ValueError when no target is identified) and
            # the network-config build, so keep the message generic enough to
            # cover either source of failure.
            pre_execute_fail_flag = True
            pre_execute_fail_message = (
                "Could not resolve targets or build network configurations: "
                f"{type(e).__name__} - {e}"
            )
        else:
            try:
                # Compile pre-execution signatures
                execution_signatures = signature_manager.build_execution_signatures(
                    config=configs
                )
            except Exception as e:
                pre_execute_fail_flag = True
                pre_execute_fail_message = (
                    f"Could not build execution signatures: {type(e).__name__} - {e}"
                )

        execution_result_outputs = None
        tool_output = {}
        execution_action = "complete"

        if pre_execute_fail_flag:
            execution_message = f"Pre-execution failure: {pre_execute_fail_message}"
            execution_status = "ERROR"
        else:
            # Execute inject
            try:
                execution_result = self.nuclei_execution(start, msg_data)
                execution_message = execution_result.get("message")
                execution_result_outputs = execution_result.get("outputs")
                execution_status = "SUCCESS"
            except Exception as e:
                execution_message = str(e)
                execution_status = "ERROR"
                tool_output = {"error_info": {"exit_code": 1}}

        callback_data = {
            "execution_message": execution_message,
            "execution_status": execution_status,
            "execution_duration": int(time.time() - start),
            "execution_action": execution_action,
        }

        if execution_result_outputs:
            callback_data["execution_output_structured"] = json.dumps(
                execution_result_outputs
            )

        self.helper.api.inject.execution_callback(
            inject_id=msg_data.inject_id, data=callback_data
        )

        if pre_execute_fail_flag:
            return

        # Compile post-execution signatures
        signature_manager.post_execution_updates(
            execution_details=execution_details,
            execution_signatures=execution_signatures,
            tool_output=tool_output,
        )

        # Build payload with extra
        expectation_signatures = signature_manager.build_payload(
            execution_signatures=execution_signatures,
            targets_meta=msg_data.targets_meta,
            expectation_types=msg_data.expectation_types,
            extra_signatures=ExtraSignatureData(
                vulnerability={
                    "cves_tested": [],
                    "cves_found_vulnerable": [],
                }
            ),
        )

        # Send signature to backend
        signature_manager.send_signatures(
            inject_id=msg_data.inject_id,
            execution_details=execution_details,
            signatures=expectation_signatures,
        )

    @staticmethod
    def _check_nuclei_installed():
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
    OpenAEVNuclei().start()
