import json
import subprocess
import threading
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
from strix.configuration.config_loader import ConfigLoader
from strix.helpers.strix_command_builder import StrixCommandBuilder
from strix.helpers.strix_output_parser import StrixOutputParser
from strix.helpers.strix_process import StrixProcess
from strix.models.data import MessageData

# Security platform identity declared by this injector, so the platform can
# attribute VULNERABILITY expectation verdicts to a real "Strix" entry (logo and
# all), the same way the Nuclei injector registers itself.
SECURITY_PLATFORM_NAME = "Strix"
SECURITY_PLATFORM_TYPE = "VULNERABILITY_SCANNER"
SECURITY_PLATFORM_DESCRIPTION = (
    "Strix runs autonomous AI penetration-testing agents that find and validate "
    "vulnerabilities with proofs-of-concept. This platform entry is managed by "
    "the Strix injector and receives the vulnerability verdicts of its runs."
)
SECURITY_PLATFORM_LOGO_PATH = "strix/img/strix.png"

_STDERR_LOG_TAIL = 2000


class OpenAEVStrix:
    def __init__(self):
        self.config_loader = ConfigLoader()
        self.config = OpenAEVConfigHelper.from_configuration_object(
            self.config_loader.to_daemon_config()
        )
        intercept_dump_argument(self.config.get_config_obj())
        self.helper = OpenAEVInjectorHelper(
            self.config, open(SECURITY_PLATFORM_LOGO_PATH, "rb")
        )

        if not self._check_strix_installed():
            raise RuntimeError(
                "Strix is not installed or is not accessible from your PATH."
            )
        self.parser = StrixOutputParser()

        # The consumer spawns one thread per inject; Strix runs are heavy (a
        # sandbox container plus an LLM), so bound how many run at once. Extra
        # injects wait for a slot instead of exhausting the host.
        max_scans = max(1, int(self.config_loader.strix.max_concurrent_scans))
        self._scan_slots = threading.BoundedSemaphore(max_scans)

    def strix_execution(self, start: float, msg_data: MessageData) -> Dict:
        targets = msg_data.get_targets()
        builder = StrixCommandBuilder(
            strix_configs=self.config_loader.strix,
            content=msg_data.inject_content,
            targets=targets,
        )
        strix_args = builder.build()

        # Per-inject LLM overrides from the contract fields (llm_model /
        # llm_api_base). Empty -> fall back to the injector defaults. The API
        # key is never a per-inject field (no masked field type), so it always
        # comes from the injector configuration.
        content = msg_data.inject_content or {}

        def _scalar(value):
            if isinstance(value, list):
                value = value[0] if value else None
            return value.strip() if isinstance(value, str) and value.strip() else None

        llm_overrides = {
            "llm_model": _scalar(content.get("llm_model")),
            "llm_api_base": _scalar(content.get("llm_api_base")),
        }

        # Do not log the raw command at INFO (an instruction may carry test
        # credentials); log the target count and scan mode instead.
        effective_model = llm_overrides["llm_model"] or self.config_loader.strix.llm_model
        self.helper.injector_logger.info(
            f"Executing Strix on {len(targets)} target(s) "
            f"[mode={strix_args[strix_args.index('--scan-mode') + 1]}, "
            f"model={effective_model}]"
        )

        callback_data = {
            "execution_message": Targets.build_execution_message(
                selector_key=msg_data.selector_key,
                data=msg_data.raw_data,
                command_args=["strix", f"({len(targets)} target(s))"],
            ),
            "execution_status": "INFO",
            "execution_duration": int(time.time() - start),
            "execution_action": "command_execution",
        }
        self.helper.api.inject.execution_callback(
            inject_id=msg_data.inject_id, data=callback_data
        )

        # Per-target traces so each asset-backed endpoint's result view shows the
        # assessment reached it (network contract only; code has no asset map).
        if msg_data.ip_to_asset_id_map:
            send_per_target_traces(
                self.helper,
                msg_data.inject_id,
                msg_data.ip_to_asset_id_map,
                label="strix assessment",
                start=start,
            )

        # 0 (or unset) disables the injector-side wall-clock: the agent then
        # stops on its own (finish_scan) or its agentic budget (max-turns /
        # max-budget), not an arbitrary timer.
        scan_timeout = self.config_loader.strix.scan_timeout or None
        try:
            with self._scan_slots:
                result = StrixProcess.execute(
                    strix_args,
                    self.config_loader.strix,
                    timeout=scan_timeout,
                    llm_overrides=llm_overrides,
                )
        except subprocess.TimeoutExpired as exc:
            stderr_tail = (exc.stderr or b"").decode("utf-8", "replace").strip()
            self.helper.injector_logger.error(
                f"Strix assessment timed out after {scan_timeout}s for inject "
                f"{msg_data.inject_id}. stderr tail: "
                f"{stderr_tail[-_STDERR_LOG_TAIL:] or '<none>'}"
            )
            raise RuntimeError(
                f"Strix assessment timed out after {scan_timeout} seconds and was "
                "terminated. Reduce scope (fewer targets, scan mode quick/standard) "
                "or lower STRIX_MAX_TURNS / set STRIX_MAX_BUDGET_USD."
            ) from exc

        if result.stderr.strip():
            self.helper.injector_logger.info(
                f"Strix finished for inject {msg_data.inject_id} in "
                f"{int(time.time() - start)}s. stderr tail: "
                f"{result.stderr.strip()[-_STDERR_LOG_TAIL:]}"
            )

        # Parse whatever Strix wrote, regardless of exit code.
        parsed = self.parser.parse(result.run_dir, msg_data.ip_to_asset_id_map)

        if result.returncode != 0:
            # Non-zero exit (e.g. MaxTurnsExceeded, config error). Best-effort:
            # if Strix still produced findings/report, surface them as a PARTIAL
            # success instead of a hard error. Only when nothing usable was
            # written do we raise a terminal error.
            stdout_tail = result.stdout.strip()
            stderr_tail = result.stderr.strip()
            detail = (stderr_tail or stdout_tail)[-_STDERR_LOG_TAIL:] or "no output captured"
            outputs = parsed.get("outputs") or {}
            has_partial = bool(
                outputs.get("cve")
                or outputs.get("others")
                or outputs.get("action_output")
            )
            if has_partial:
                self.helper.injector_logger.warning(
                    f"Strix exited with code {result.returncode} for inject "
                    f"{msg_data.inject_id} but wrote partial results; surfacing "
                    f"them. Detail: {detail}"
                )
                parsed["message"] = (
                    f"Strix run incomplete (exit {result.returncode}) - partial "
                    f"results surfaced. " + parsed.get("message", "")
                )
                return parsed
            self.helper.injector_logger.error(
                f"Strix exited with code {result.returncode} for inject "
                f"{msg_data.inject_id} with no usable results. Detail: {detail}"
            )
            raise RuntimeError(
                f"Strix exited with code {result.returncode}: {detail}"
            )

        return parsed

    def _report_pre_execution_failure(
        self, data: Dict, start: float, err: Exception
    ) -> None:
        injection = data.get("injection") if isinstance(data, dict) else None
        inject_id = injection.get("inject_id") if isinstance(injection, dict) else None
        if not inject_id:
            self.helper.injector_logger.error(
                "strix pre-execution failure with unresolvable inject id: " + str(err)
            )
            return
        self.helper.injector_logger.error("strix pre-execution failure: " + str(err))
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

        try:
            msg_data = MessageData(data, self.helper)
        except Exception as err:
            self._report_pre_execution_failure(data, start, err)
            return

        self.helper.api.inject.execution_reception(
            inject_id=msg_data.inject_id, data={"tracking_total_count": 1}
        )

        signature_manager = SignatureManager(self.helper.api)
        execution_details = ExecutionDetails()

        pre_execute_fail_flag = False
        pre_execute_fail_message = ""
        execution_signatures = None

        try:
            targets = msg_data.get_targets()
            # Signatures are network-oriented; the code contract has no network
            # targets, so it skips signature compilation entirely.
            if msg_data.ip_to_asset_id_map or not msg_data.is_code_assessment:
                configs = build_network_configs(targets)
                execution_signatures = signature_manager.build_execution_signatures(
                    config=configs
                )
        except Exception as e:
            pre_execute_fail_flag = True
            pre_execute_fail_message = (
                "Could not resolve targets or build execution signatures: "
                f"{type(e).__name__} - {e}"
            )

        execution_result_outputs = None
        tool_output: Dict = {}

        if pre_execute_fail_flag:
            execution_message = f"Pre-execution failure: {pre_execute_fail_message}"
            execution_status = "ERROR"
        else:
            try:
                execution_result = self.strix_execution(start, msg_data)
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
            "execution_action": "complete",
        }
        if execution_result_outputs:
            callback_data["execution_output_structured"] = json.dumps(
                execution_result_outputs
            )
        try:
            self.helper.api.inject.execution_callback(
                inject_id=msg_data.inject_id, data=callback_data
            )
        except Exception as cb_err:
            # A late callback is rejected by the platform (409 integrity
            # violation) when the inject already expired because the run
            # exceeded inject.execution.threshold.minutes. Log and stop here so
            # the RabbitMQ data-handler thread does not die and the injector
            # keeps consuming. The signature updates below would 409 too.
            self.helper.injector_logger.error(
                "execution_callback rejected, inject likely already finalized on "
                "the platform (run too long?): "
                f"{type(cb_err).__name__} - {cb_err}"
            )
            return

        if pre_execute_fail_flag or execution_signatures is None:
            return

        signature_manager.post_execution_updates(
            execution_details=execution_details,
            execution_signatures=execution_signatures,
            tool_output=tool_output,
        )
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
        signature_manager.send_signatures(
            inject_id=msg_data.inject_id,
            execution_details=execution_details,
            signatures=expectation_signatures,
        )

    @staticmethod
    def _check_strix_installed() -> bool:
        try:
            StrixProcess.strix_version()
            return True
        except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return False

    def _register_security_platform(self) -> None:
        """Declare Strix as a security platform (best-effort)."""
        try:
            with open(SECURITY_PLATFORM_LOGO_PATH, "rb") as logo:
                document = self.helper.api.document.upsert(
                    document={}, file=("strix.png", logo, "image/png")
                )
            self.helper.api.security_platform.upsert(
                {
                    "asset_name": SECURITY_PLATFORM_NAME,
                    "asset_external_reference": self.config.get_conf(
                        "injector_type", default="openaev_strix"
                    ),
                    "asset_description": SECURITY_PLATFORM_DESCRIPTION,
                    "security_platform_type": SECURITY_PLATFORM_TYPE,
                    "security_platform_logo_light": document.get("document_id"),
                    "security_platform_logo_dark": document.get("document_id"),
                }
            )
            self.helper.injector_logger.info(
                "Registered Strix as a security platform (vulnerability scanner)"
            )
        except Exception as err:
            self.helper.injector_logger.warning(
                "Could not register Strix as a security platform (requires an "
                "OpenAEV version supporting the VULNERABILITY_SCANNER platform "
                "type): " + str(err)
            )

    def start(self):
        self._register_security_platform()
        self.helper.listen(message_callback=self.process_message)


if __name__ == "__main__":
    OpenAEVStrix().start()
