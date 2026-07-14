import json
import time
from typing import Dict, Optional

from azure_injector.configuration.config_loader import ConfigLoader
from pyoaev.helpers import OpenAEVConfigHelper, OpenAEVInjectorHelper

from injector_common.data_helpers import DataHelpers
from injector_common.dump_config import intercept_dump_argument
from injector_common.stratus_executor import StratusExecutor

ICON_PATH = "azure_injector/img/icon-azure.png"


class OpenAEVAzure:
    def __init__(self):
        self.config = OpenAEVConfigHelper.from_configuration_object(
            ConfigLoader().to_daemon_config()
        )
        intercept_dump_argument(self.config.get_config_obj())
        with open(ICON_PATH, "rb") as icon_file:
            icon_bytes = icon_file.read()
        self.helper = OpenAEVInjectorHelper(self.config, icon_bytes)
        self.stratus = StratusExecutor(logger=self.helper.injector_logger)

    @staticmethod
    def _resolve_technique(content: Dict) -> Optional[str]:
        custom = content.get("custom_technique_id")
        if custom:
            return custom.strip()
        selected = content.get("technique_id")
        if isinstance(selected, list):
            return selected[0] if selected else None
        return selected

    def _build_env(self, content: Dict) -> Dict[str, str]:
        return {
            "AZURE_TENANT_ID": content.get("azure_tenant_id"),
            "AZURE_SUBSCRIPTION_ID": content.get("azure_subscription_id"),
            "AZURE_CLIENT_ID": content.get("azure_client_id"),
            "AZURE_CLIENT_SECRET": content.get("azure_client_secret"),
        }

    def process_message(self, data: Dict) -> None:
        start = time.time()
        inject_id = DataHelpers.get_inject_id(data)
        self.helper.api.inject.execution_reception(
            inject_id=inject_id, data={"tracking_total_count": 1}
        )

        try:
            content = DataHelpers.get_content(data)
            technique_id = self._resolve_technique(content)
            if not technique_id:
                raise ValueError("No Stratus technique id provided")

            result = self.stratus.detonate(
                technique_id, env=self._build_env(content), cleanup=True
            )

            if result.success:
                callback_data = {
                    "execution_message": result.message,
                    "execution_output_structured": json.dumps(result.outputs),
                    "execution_status": "SUCCESS",
                    "execution_duration": int(time.time() - start),
                    "execution_action": "complete",
                }
            else:
                callback_data = {
                    "execution_message": result.message,
                    "execution_status": "ERROR",
                    "execution_duration": int(time.time() - start),
                    "execution_action": "complete",
                }
            self.helper.api.inject.execution_callback(
                inject_id=inject_id, data=callback_data
            )
        except Exception as e:
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
        self.helper.injector_logger.info("Starting Azure injector...")
        self.helper.listen(message_callback=self.process_message)


if __name__ == "__main__":
    OpenAEVAzure().start()
