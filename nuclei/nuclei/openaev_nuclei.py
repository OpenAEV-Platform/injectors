import json
import subprocess
import time
from typing import Dict, Optional

from pyoaev.helpers import OpenAEVConfigHelper, OpenAEVInjectorHelper
from pyoaev.signatures import (
    ExtraSignatureData,
    SignatureManager,
    build_network_configs,
)
from pyoaev.signatures.models import ExecutionDetails

from injector_common.dump_config import intercept_dump_argument
from injector_common.targets import Targets
from injector_common.traces import send_per_target_traces
from nuclei.configuration.config_loader import ConfigLoader
from nuclei.helpers.nuclei_command_builder import NucleiCommandBuilder
from nuclei.helpers.nuclei_output_parser import NucleiOutputParser
from nuclei.helpers.nuclei_process import NucleiProcess
from nuclei.models.data import MessageData
from nuclei.nuclei_contracts.external_contracts import ExternalContractsScheduler

# Security platform identity declared by this injector. Nuclei performs the
# vulnerability assessment itself, so the platform can attribute VULNERABILITY
# expectation verdicts to a real "Nuclei" security platform entry (logo and
# all), the same way detection/prevention verdicts are attributed to EDR/SIEM
# platforms instead of a generic manager.
SECURITY_PLATFORM_NAME = "Nuclei"
SECURITY_PLATFORM_TYPE = "VULNERABILITY_SCANNER"
SECURITY_PLATFORM_DESCRIPTION = (
    "Nuclei is a fast, template-based vulnerability scanner. This platform "
    "entry is managed by the Nuclei injector and receives the vulnerability "
    "verdicts of its scans."
)
SECURITY_PLATFORM_LOGO_PATH = "nuclei/img/nuclei.jpg"

# Max characters of Nuclei's captured stderr kept in a log line, so a very
# noisy scan cannot flood the injector logs.
_STDERR_LOG_TAIL = 2000


def _decode(raw: Optional[bytes]) -> str:
    """Best-effort decode of captured subprocess output for logging/errors."""
    return (raw or b"").decode("utf-8", "replace").strip()


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

        # Per-target traces so each asset-backed endpoint's result view shows the
        # scan reached it; the batched scan only sends a global callback otherwise.
        send_per_target_traces(
            self.helper,
            msg_data.inject_id,
            msg_data.target_results.ip_to_asset_id_map,
            label="nuclei scan",
            start=start,
        )

        input_data = ("\n".join(targets) + "\n").encode("utf-8")
        scan_timeout = self.config_loader.nuclei.scan_timeout
        try:
            result = NucleiProcess.nuclei_execute(
                nuclei_args, input_data, timeout=scan_timeout
            )
        except subprocess.TimeoutExpired as exc:
            # A hung scan must not block the consumer forever: Nuclei's own
            # -timeout is per-request, so only this ceiling bounds the whole run.
            # Surface the partial output and re-raise so process_message emits a
            # terminal ERROR callback - otherwise the inject stays PENDING until
            # the platform's stale-inject sweep marks it failed with no reason.
            stderr_tail = _decode(exc.stderr)
            self.helper.injector_logger.error(
                f"Nuclei scan timed out after {scan_timeout}s for inject "
                f"{msg_data.inject_id} and was terminated. Nuclei stderr tail: "
                f"{stderr_tail[-_STDERR_LOG_TAIL:] or '<none>'}"
            )
            raise RuntimeError(
                f"Nuclei scan timed out after {scan_timeout} seconds and was "
                "terminated before completion. Reduce the scan scope (tags / "
                "manual template path / fewer targets) or raise NUCLEI_SCAN_TIMEOUT."
            ) from exc
        except subprocess.CalledProcessError as exc:
            # Non-zero exit: bubble up the stderr so the terminal error trace is
            # actionable instead of a bare "returned non-zero exit status N".
            stderr_tail = _decode(exc.stderr)
            self.helper.injector_logger.error(
                f"Nuclei exited with code {exc.returncode} for inject "
                f"{msg_data.inject_id}. Nuclei stderr tail: "
                f"{stderr_tail[-_STDERR_LOG_TAIL:] or '<none>'}"
            )
            raise RuntimeError(
                f"Nuclei exited with code {exc.returncode}: "
                f"{stderr_tail[-_STDERR_LOG_TAIL:] or 'no stderr output'}"
            ) from exc

        # Nuclei writes its runtime progress and warnings to stderr; log it so a
        # completed scan is no longer silent between "Executing nuclei with ..."
        # and the results.
        stderr_tail = _decode(result.stderr)
        if stderr_tail:
            self.helper.injector_logger.info(
                f"Nuclei finished for inject {msg_data.inject_id} in "
                f"{int(time.time() - start)}s. Nuclei stderr tail: "
                f"{stderr_tail[-_STDERR_LOG_TAIL:]}"
            )

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

    def _register_security_platform(self) -> None:
        """Declare Nuclei as a security platform (best-effort).

        The upsert is keyed on the injector type (``asset_external_reference``)
        so every Nuclei injector deployment shares one platform entry, and so
        the backend can attribute vulnerability verdicts to it by resolving the
        inject's injector type. Registration is best-effort: backends that do
        not support the VULNERABILITY_SCANNER platform type yet reject the
        call, and the injector must keep working exactly as before.
        """
        try:
            with open(SECURITY_PLATFORM_LOGO_PATH, "rb") as logo:
                document = self.helper.api.document.upsert(
                    document={}, file=("nuclei.jpg", logo, "image/jpeg")
                )
            self.helper.api.security_platform.upsert(
                {
                    "asset_name": SECURITY_PLATFORM_NAME,
                    "asset_external_reference": self.config.get_conf(
                        "injector_type", default="openaev_nuclei"
                    ),
                    "asset_description": SECURITY_PLATFORM_DESCRIPTION,
                    "security_platform_type": SECURITY_PLATFORM_TYPE,
                    "security_platform_logo_light": document.get("document_id"),
                    "security_platform_logo_dark": document.get("document_id"),
                }
            )
            self.helper.injector_logger.info(
                "Registered Nuclei as a security platform (vulnerability scanner)"
            )
        except Exception as err:
            self.helper.injector_logger.warning(
                "Could not register Nuclei as a security platform (requires an "
                "OpenAEV version supporting the VULNERABILITY_SCANNER platform "
                "type): " + str(err)
            )

    def start(self):
        self._register_security_platform()
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
