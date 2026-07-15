import json
import time
from typing import Dict

from pyoaev.helpers import OpenAEVConfigHelper, OpenAEVInjectorHelper

from ai_redteam import marker as marker_mod
from ai_redteam.configuration.config_loader import ConfigLoader
from ai_redteam.engines import build_registry, contract_engine_map
from ai_redteam.targets.target_resolver import resolve_targets

try:
    from injector_common.dump_config import intercept_dump_argument
except ImportError:  # pragma: no cover - dump tooling is optional in local dev

    def intercept_dump_argument(_):
        return None


class OpenAEVAiRedTeam:
    def __init__(self):
        self.config = OpenAEVConfigHelper.from_configuration_object(
            ConfigLoader().to_daemon_config()
        )
        intercept_dump_argument(self.config.get_config_obj())
        self.helper = OpenAEVInjectorHelper(
            self.config, open("ai_redteam/img/icon-ai-redteam.png", "rb")
        )
        timeout = int(self.config.get_conf("injector_request_timeout_seconds") or 120)
        self.engines_timeout = timeout
        self.engines = build_registry(timeout=timeout)
        self.engine_by_contract = contract_engine_map()

    def _resolve_engine(self, contract_id):
        engine_key = self.engine_by_contract.get(contract_id, "native")
        return self.engines.get(engine_key), engine_key

    def ai_execution(self, start: float, data: Dict) -> Dict:
        injection = data["injection"]
        inject_id = injection["inject_id"]
        contract_id = injection["inject_injector_contract"]["convertedContent"][
            "contract_id"
        ]
        content = injection.get("inject_content") or {}

        logger = self.helper.injector_logger

        logger.info(
            f"Received inject {inject_id} for contract {contract_id}; "
            f"content keys: {sorted(content.keys())}"
        )

        engine, engine_key = self._resolve_engine(contract_id)
        if engine is None:
            raise ValueError(f"No engine registered for contract {contract_id}")

        marker = marker_mod.build_marker(inject_id)
        targets = resolve_targets(content, data, self.helper.api, logger)

        logger.info(
            f"Resolved {len(targets)} AI target(s) for inject {inject_id}: "
            + ", ".join(
                f"[{self._target_label(t)}] provider='{t.provider}' "
                f"model='{t.model}' endpoint='{t.endpoint or '(default)'}'"
                for t in targets
            )
        )

        logger.info(
            f"Running AI red-team engine '{engine_key}' against {len(targets)} "
            f"target(s) for inject {inject_id} with marker {marker} "
            f"(timeout={self.engines_timeout}s)"
        )

        # Intermediate trace so the timeline shows the action with the correlation marker
        try:
            self.helper.api.inject.execution_callback(
                inject_id=inject_id,
                data={
                    "execution_message": (
                        f"AI red-team engine '{engine_key}' targeting {len(targets)} "
                        f"AI target(s) (marker {marker})"
                    ),
                    "execution_status": "INFO",
                    "execution_duration": int(time.time() - start),
                    "execution_action": "command_execution",
                },
            )
            logger.info(f"Intermediate execution trace sent for inject {inject_id}")
        except Exception as exc:  # noqa: BLE001
            logger.error(
                f"Failed to send intermediate execution trace for inject "
                f"{inject_id}: {exc}"
            )

        logger.info(f"Invoking engine '{engine_key}' run() for inject {inject_id}...")
        results = []
        for target in targets:
            result = engine.run(
                content, target, marker, ctx={"inject_id": inject_id, "logger": logger}
            )
            logger.info(
                f"Engine '{engine_key}' finished for target "
                f"'{self._target_label(target)}' (inject {inject_id}): "
                f"status={result.status}, success={result.success}, "
                f"output_keys={sorted((result.outputs or {}).keys())}"
            )
            results.append(result)

        return self._aggregate_results(targets, results)

    @staticmethod
    def _target_label(target) -> str:
        return target.name or target.endpoint or target.model or target.provider

    def _aggregate_results(self, targets, results) -> Dict:
        """Collapse per-target engine results into a single inject execution callback.

        A single target keeps the original single-result shape. Multiple targets (asset-group
        mode) are merged: the message lists each target's verdict, the `vulnerability` outputs
        are concatenated (tagged with the target), and per-target responses are keyed by label.
        """
        if len(results) == 1:
            result = results[0]
            return {
                "message": result.message,
                "status": result.status,
                "outputs": result.outputs,
            }

        vulnerabilities = []
        responses = {}
        message_lines = []
        for target, result in zip(targets, results):
            label = self._target_label(target)
            outputs = result.outputs or {}
            responses[label] = outputs.get("response", "")
            for vuln in outputs.get("vulnerability", []) or []:
                enriched = dict(vuln)
                enriched["target"] = label
                vulnerabilities.append(enriched)
            verdict = (
                "ERROR"
                if result.status == "ERROR"
                else ("VULNERABLE" if result.success else "DEFENDED")
            )
            message_lines.append(f"- [{verdict}] {label}")

        any_success = any(r.success for r in results)
        all_error = all(r.status == "ERROR" for r in results)

        outputs = {
            "response": "\n\n".join(
                f"### {label}\n{text}" for label, text in responses.items() if text
            ),
            "marker": (results[0].outputs or {}).get("marker", ""),
            "attack_succeeded": any_success,
            "responses_by_target": responses,
        }
        if vulnerabilities:
            outputs["vulnerability"] = vulnerabilities

        summary = (
            f"Tested {len(targets)} AI target(s): "
            f"{sum(1 for r in results if r.success)} vulnerable, "
            f"{sum(1 for r in results if not r.success and r.status != 'ERROR')} defended, "
            f"{sum(1 for r in results if r.status == 'ERROR')} error(s).\n\n"
            + "\n".join(message_lines)
        )
        # ERROR only when every target failed to execute; otherwise the inject ran.
        status = "ERROR" if all_error else "SUCCESS"
        return {"message": summary, "status": status, "outputs": outputs}

    def process_message(self, data: Dict) -> None:
        start = time.time()
        inject_id = data["injection"]["inject_id"]
        logger = self.helper.injector_logger
        logger.info(f"Message received from queue for inject {inject_id}")
        self.helper.api.inject.execution_reception(
            inject_id=inject_id, data={"tracking_total_count": 1}
        )
        logger.info(f"Execution reception acknowledged for inject {inject_id}")
        try:
            result = self.ai_execution(start, data)
            logger.info(
                f"Sending completion callback for inject {inject_id} "
                f"(status={result['status']}, duration={int(time.time() - start)}s)"
            )
            self.helper.api.inject.execution_callback(
                inject_id=inject_id,
                data={
                    "execution_message": result["message"],
                    "execution_output_structured": json.dumps(result["outputs"]),
                    "execution_status": result["status"],
                    "execution_duration": int(time.time() - start),
                    "execution_action": "complete",
                },
            )
            logger.info(f"Completion callback sent for inject {inject_id}")
        except Exception as e:  # noqa: BLE001
            logger.error(f"Execution failed for inject {inject_id}: {e}")
            self.helper.api.inject.execution_callback(
                inject_id=inject_id,
                data={
                    "execution_message": str(e),
                    "execution_status": "ERROR",
                    "execution_duration": int(time.time() - start),
                    "execution_action": "complete",
                },
            )
            logger.info(f"Error callback sent for inject {inject_id}")

    def start(self):
        self.helper.listen(message_callback=self.process_message)


if __name__ == "__main__":
    OpenAEVAiRedTeam().start()
