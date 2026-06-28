import json
import time
from typing import Dict

from pyoaev.helpers import OpenAEVConfigHelper, OpenAEVInjectorHelper

from ai_redteam import marker as marker_mod
from ai_redteam.configuration.config_loader import ConfigLoader
from ai_redteam.engines import build_registry, contract_engine_map
from ai_redteam.targets.target_resolver import resolve_target

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

        engine, engine_key = self._resolve_engine(contract_id)
        if engine is None:
            raise ValueError(f"No engine registered for contract {contract_id}")

        marker = marker_mod.build_marker(inject_id)
        target = resolve_target(content, self.helper.api, self.helper.injector_logger)

        self.helper.injector_logger.info(
            f"Running AI red-team engine '{engine_key}' against provider "
            f"'{target.provider}' (model={target.model}) for inject {inject_id}"
        )

        # Intermediate trace so the timeline shows the action with the correlation marker
        self.helper.api.inject.execution_callback(
            inject_id=inject_id,
            data={
                "execution_message": (
                    f"AI red-team engine '{engine_key}' targeting {target.provider} "
                    f"endpoint '{target.endpoint or 'default'}' (marker {marker})"
                ),
                "execution_status": "INFO",
                "execution_duration": int(time.time() - start),
                "execution_action": "command_execution",
            },
        )

        result = engine.run(content, target, marker, ctx={"inject_id": inject_id})
        return {
            "message": result.message,
            "status": result.status,
            "outputs": result.outputs,
        }

    def process_message(self, data: Dict) -> None:
        start = time.time()
        inject_id = data["injection"]["inject_id"]
        self.helper.api.inject.execution_reception(
            inject_id=inject_id, data={"tracking_total_count": 1}
        )
        try:
            result = self.ai_execution(start, data)
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
        except Exception as e:  # noqa: BLE001
            self.helper.api.inject.execution_callback(
                inject_id=inject_id,
                data={
                    "execution_message": str(e),
                    "execution_status": "ERROR",
                    "execution_duration": int(time.time() - start),
                    "execution_action": "complete",
                },
            )

    def start(self):
        self.helper.listen(message_callback=self.process_message)


if __name__ == "__main__":
    OpenAEVAiRedTeam().start()
