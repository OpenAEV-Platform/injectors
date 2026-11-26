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

from injector_common.callbacks import call_with_retry
from injector_common.dump_config import intercept_dump_argument
from injector_common.inject_gone import abort_on_inject_gone, is_inject_gone
from injector_common.outcomes import (
    ERROR,
    EXECUTED,
    WARNING,
    send_scan_progress_trace,
    send_skipped_asset_traces,
    send_target_outcome_traces,
)
from injector_common.scan_budget import SCAN_TIMEOUT_FIELD, resolve_scan_timeout
from injector_common.targets import Targets
from nmap.configuration.config_loader import ConfigLoader
from nmap.contracts.nmap_constants import HOST_TIMEOUT_KEY, MAX_RETRIES_KEY
from nmap.helpers.nmap_command_builder import NmapCommandBuilder
from nmap.helpers.nmap_output_parser import NmapOutputParser
from nmap.helpers.nmap_stream_runner import run_nmap
from nmap.models.data import MessageData


class OpenAEVNmap:
    def __init__(self):
        self.config_loader = ConfigLoader()
        self.config = OpenAEVConfigHelper.from_configuration_object(
            self.config_loader.to_daemon_config()
        )
        intercept_dump_argument(self.config.get_config_obj())
        self.helper = OpenAEVInjectorHelper(
            self.config, open("nmap/img/icon-nmap.png", "rb")
        )
        self.signature_manager = SignatureManager(self.helper.api)

    def nmap_execution(self, start: float, msg_data: MessageData) -> dict:
        # Build Arguments to execute
        targets = msg_data.get_targets()
        nmap_args = NmapCommandBuilder.build_args(
            msg_data.contract_id,
            targets,
            msg_data.scan_options,
            defaults=self.tuning_defaults(),
        )
        scan_timeout = self.scan_timeout_for(msg_data.scan_timeout)

        self.helper.injector_logger.info(
            "Executing nmap with command: " + " ".join(nmap_args)
        )

        message = Targets.build_execution_message(
            selector_key=msg_data.selector_key,
            data=msg_data.raw_data,
            command_args=nmap_args,
            target_results=msg_data.target_results,
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

        # Assets that got no target value are not scanned: one WARNING trace each,
        # on its asset, with the reason.
        skipped = Targets.skipped_of(msg_data.target_results)
        send_skipped_asset_traces(self.helper, msg_data.inject_id, skipped, start)

        # One run covers every target: say how many, and the platform timeout a long
        # run may hit, before it starts.
        send_scan_progress_trace(
            self.helper,
            msg_data.inject_id,
            len(targets or []),
            label="nmap scan",
            start=start,
        )

        # Each host is reported the moment nmap finishes it (its <host> element is
        # written to stdout then), not only once the whole group is scanned.
        reported: set = set()

        def report_host(host_xml: bytes) -> None:
            outcomes = [
                o
                for o in NmapOutputParser.host_outcomes(
                    host_xml, msg_data.target_results
                )
                if o.resolution.target.lower() not in reported
            ]
            reported.update(o.resolution.target.lower() for o in outcomes)
            send_target_outcome_traces(self.helper, msg_data.inject_id, outcomes, start)

        try:
            nmap_result = run_nmap(nmap_args, timeout=scan_timeout, on_host=report_host)
        except subprocess.TimeoutExpired as exc:
            # nmap is killed at the scan time limit, below the platform inject
            # execution threshold, so the inject still gets its results: the hosts
            # nmap finished (written to stdout as it goes) are kept, the others are
            # marked not scanned.
            self.helper.injector_logger.warning(
                f"nmap terminated at its {scan_timeout}s scan time limit for inject "
                f"{msg_data.inject_id}; keeping the hosts already scanned."
            )
            result = NmapOutputParser.xmlparse(
                NmapOutputParser.salvage_partial(exc.stdout),
                msg_data.selector_key,
                msg_data.target_results,
                stderr=exc.stderr,
                time_limit_seconds=scan_timeout,
            )
        else:
            result = self._parse_result(nmap_args, nmap_result, msg_data)
        # After the run: one trace per target not reported while nmap ran (not
        # scanned, unresolved), on its asset.
        send_target_outcome_traces(
            self.helper,
            msg_data.inject_id,
            [
                o
                for o in result.get("outcomes") or []
                if o.resolution.target.lower() not in reported
            ],
            start,
        )
        if skipped:
            # A skipped asset is a partial result: the completion says how many and
            # is WARNING, as for a target the scan missed.
            result["message"] = (
                f"{result.get('message', '')}\n"
                f"{msg_data.target_results.describe_skipped()}"
            ).lstrip("\n")
            if (result.get("status") or EXECUTED) == EXECUTED:
                result["status"] = WARNING
        return result

    def tuning_defaults(self) -> dict:
        """The safe defaults applied to the timing fields an inject leaves empty."""
        nmap_config = self.config_loader.nmap
        return {
            HOST_TIMEOUT_KEY: nmap_config.default_host_timeout_seconds,
            MAX_RETRIES_KEY: nmap_config.default_max_retries,
        }

    def scan_timeout_for(self, inject_value) -> int:
        """The whole-run ceiling of one inject, in seconds: the inject field
        scan_timeout_seconds, else NMAP_SCAN_TIMEOUT, else derived from the
        platform inject execution threshold (injector_common.scan_budget)."""
        return resolve_scan_timeout(
            self.helper,
            {SCAN_TIMEOUT_FIELD: inject_value},
            self.config_loader.nmap.scan_timeout,
        )

    @staticmethod
    def _parse_result(nmap_args, nmap_result, msg_data: MessageData) -> dict:
        """Parse the report. On a non-zero exit, a report that still parses is kept:
        the inject ends WARNING with the exit code and nmap's stderr when at least one
        target was scanned, ERROR when none was. A report that does not parse raises
        the CalledProcessError so the inject ends ERROR with nmap's stderr."""
        returncode = nmap_result.returncode
        try:
            return NmapOutputParser.xmlparse(
                nmap_result.stdout,
                msg_data.selector_key,
                msg_data.target_results,
                stderr=nmap_result.stderr,
                exit_code=returncode,
            )
        except Exception:
            if not returncode:
                raise
            raise subprocess.CalledProcessError(
                returncode,
                nmap_args,
                output=nmap_result.stdout,
                stderr=nmap_result.stderr,
            ) from None

    def _report_pre_execution_failure(
        self, data: dict, start: float, err: Exception, skipped=None
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
        # Every asset skipped: one WARNING trace each before the ERROR completion.
        send_skipped_asset_traces(self.helper, inject_id, skipped, start)
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
        # A 404 on any callback means the inject was deleted on the platform:
        # stop with one log line, never a traceback in the per-message thread.
        with abort_on_inject_gone(self.helper.injector_logger, data):
            self._process_message(data)

    def _process_message(self, data: dict) -> None:
        start = time.time()

        # unpacking the message, resolving targets and building the pre-execution
        # signatures can all raise (invalid payload, no targets, signature setup);
        # guard them so a failure is reported instead of propagating out.
        msg_data = None
        try:
            msg_data = MessageData(data, self.helper)
            targets = msg_data.get_targets()
            network_injector_configs = build_network_configs(targets)
            execution_signatures = self.signature_manager.build_execution_signatures(
                network_injector_configs
            )
        except Exception as err:
            # When every asset was skipped get_targets raises and nmap never runs; the
            # skipped assets still get their traces.
            skipped = Targets.skipped_of(msg_data.target_results) if msg_data else []
            self._report_pre_execution_failure(data, start, err, skipped=skipped)
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
            execution_message = (err.stderr or b"").strip().decode(
                "utf-8", errors="replace"
            ) or f"nmap exited with code {err.returncode}"
            tool_error_info = {
                "exit_code": int(err.returncode),
            }
        except Exception as err:
            if is_inject_gone(err):
                # Deleted before the scan: nmap never ran, nothing to report.
                raise
            execution_message = str(err)
            tool_error_info = {
                "exit_code": 1,
            }
        else:
            execution_message = execution_result["message"]
            if execution_result.get("status") == ERROR:
                # nmap exited non-zero and scanned no target: a failed run, whose
                # message already carries the exit code and nmap's stderr.
                tool_error_info = {
                    "exit_code": int(execution_result.get("exit_code") or 1),
                }
        tool_output = {
            "error_info": tool_error_info,
        }

        # formatting callback data and tool_output
        if tool_error_info:
            execution_status = "ERROR"
        else:
            # EXECUTED when every target answered; WARNING (a success on the
            # platform) when some were missed or nmap exited non-zero with partial
            # results kept.
            execution_status = execution_result.get("status") or "EXECUTED"
        callback_data = {
            "execution_message": execution_message,
            "execution_status": execution_status,
            "execution_action": "complete",
        }
        if execution_result:
            callback_data["execution_output_structured"] = json.dumps(
                execution_result["outputs"]
            )

        # sending execution callback
        callback_data["execution_duration"] = int(time.time() - start)
        # The terminal callback carries the whole scan: bounded retry on a
        # transient network error (a 404 or any other error raises at once).
        call_with_retry(
            lambda: self.helper.api.inject.execution_callback(
                inject_id=msg_data.inject_id, data=callback_data
            ),
            self.helper.injector_logger,
            f"Terminal callback of inject {msg_data.inject_id}",
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
