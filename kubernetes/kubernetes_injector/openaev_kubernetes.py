import json
import os
import tempfile
import time
from typing import Dict, Optional

from injector_common.data_helpers import DataHelpers
from injector_common.dump_config import intercept_dump_argument
from injector_common.stratus_executor import StratusExecutor
from pyoaev.helpers import OpenAEVConfigHelper, OpenAEVInjectorHelper

from kubernetes_injector.configuration.config_loader import ConfigLoader

ICON_PATH = "kubernetes_injector/img/icon-kubernetes.png"


class OpenAEVKubernetes:
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

        kubeconfig_path = None
        try:
            content = DataHelpers.get_content(data)
            technique_id = self._resolve_technique(content)
            if not technique_id:
                raise ValueError("No Stratus technique id provided")

            kubeconfig = content.get("kubeconfig")
            if not kubeconfig:
                raise ValueError("A kubeconfig is required")
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".yaml", delete=False
            ) as kube_file:
                kube_file.write(kubeconfig)
                kubeconfig_path = kube_file.name

            env = {"KUBECONFIG": kubeconfig_path}
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
            if kubeconfig_path and os.path.exists(kubeconfig_path):
                os.remove(kubeconfig_path)

    def start(self):
        self.helper.injector_logger.info("Starting Kubernetes injector...")
        self.helper.listen(message_callback=self.process_message)


if __name__ == "__main__":
    OpenAEVKubernetes().start()
