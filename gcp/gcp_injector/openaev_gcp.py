import json
import os
import tempfile
import time
from typing import Dict, Optional

from injector_common.data_helpers import DataHelpers
from injector_common.dump_config import intercept_dump_argument
from injector_common.stratus_executor import StratusExecutor
from pyoaev.helpers import OpenAEVConfigHelper, OpenAEVInjectorHelper

from gcp_injector.configuration.config_loader import ConfigLoader

ICON_PATH = "gcp_injector/img/icon-gcp.png"


class OpenAEVGcp:
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

    def process_message(self, data: Dict) -> None:
        start = time.time()
        inject_id = DataHelpers.get_inject_id(data)
        self.helper.api.inject.execution_reception(
            inject_id=inject_id, data={"tracking_total_count": 1}
        )

        key_path = None
        try:
            content = DataHelpers.get_content(data)
            technique_id = self._resolve_technique(content)
            if not technique_id:
                raise ValueError("No Stratus technique id provided")

            # Stratus authenticates to GCP through Application Default
            # Credentials; materialize the service account key on disk.
            key_material = content.get("gcp_service_account_key")
            if not key_material:
                raise ValueError("A GCP service account key is required")
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".json", delete=False
            ) as key_file:
                key_file.write(key_material)
                key_path = key_file.name

            env = {
                "GOOGLE_PROJECT": content.get("gcp_project_id"),
                "GOOGLE_APPLICATION_CREDENTIALS": key_path,
                "CLOUDSDK_CORE_PROJECT": content.get("gcp_project_id"),
            }

            result = self.stratus.detonate(technique_id, env=env, cleanup=True)

            callback_data = {
                "execution_message": result.message,
                "execution_status": "SUCCESS" if result.success else "ERROR",
                "execution_duration": int(time.time() - start),
                "execution_action": "complete",
            }
            if result.success:
                callback_data["execution_output_structured"] = json.dumps(
                    result.outputs
                )
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
        finally:
            if key_path and os.path.exists(key_path):
                os.remove(key_path)

    def start(self):
        self.helper.injector_logger.info("Starting GCP injector...")
        self.helper.listen(message_callback=self.process_message)


if __name__ == "__main__":
    OpenAEVGcp().start()
