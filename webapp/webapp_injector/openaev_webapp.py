import json
import time
from typing import Dict

from pyoaev.helpers import OpenAEVConfigHelper, OpenAEVInjectorHelper
from webapp_injector.configuration.config_loader import ConfigLoader
from webapp_injector.contracts_webapp import SQLMAP_CONTRACT, ZAP_BASELINE_CONTRACT
from webapp_injector.helpers.webapp_executor import WebappExecutor

from injector_common.data_helpers import DataHelpers
from injector_common.dump_config import intercept_dump_argument

ICON_PATH = "webapp_injector/img/icon-webapp.png"


class OpenAEVWebapp:
    def __init__(self):
        self.config = OpenAEVConfigHelper.from_configuration_object(
            ConfigLoader().to_daemon_config()
        )
        intercept_dump_argument(self.config.get_config_obj())
        with open(ICON_PATH, "rb") as icon_file:
            icon_bytes = icon_file.read()
        self.helper = OpenAEVInjectorHelper(self.config, icon_bytes)
        self.executor = WebappExecutor(logger=self.helper.injector_logger)

    def _dispatch(self, contract_id: str, content: Dict):
        target_url = content.get("target_url")
        if not target_url:
            raise ValueError("A target URL is required")
        if contract_id == ZAP_BASELINE_CONTRACT:
            return self.executor.run_zap_baseline(target_url)
        if contract_id == SQLMAP_CONTRACT:
            return self.executor.run_sqlmap(target_url)
        raise ValueError(f"Unsupported contract id: {contract_id}")

    def process_message(self, data: Dict) -> None:
        start = time.time()
        inject_id = DataHelpers.get_inject_id(data)
        self.helper.api.inject.execution_reception(
            inject_id=inject_id, data={"tracking_total_count": 1}
        )

        try:
            contract_id = DataHelpers.get_injector_contract_id(data)
            content = DataHelpers.get_content(data)
            result = self._dispatch(contract_id, content)

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

    def start(self):
        self.helper.injector_logger.info("Starting Web Application Attack injector...")
        self.helper.listen(message_callback=self.process_message)


if __name__ == "__main__":
    OpenAEVWebapp().start()
