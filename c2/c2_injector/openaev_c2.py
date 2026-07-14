import json
import time
from typing import Dict

from c2_injector.configuration.config_loader import ConfigLoader
from c2_injector.helpers.c2_executor import C2Executor
from pyoaev.helpers import OpenAEVConfigHelper, OpenAEVInjectorHelper

from injector_common.data_helpers import DataHelpers
from injector_common.dump_config import intercept_dump_argument

ICON_PATH = "c2_injector/img/icon-c2.png"


class OpenAEVC2:
    def __init__(self):
        self.config = OpenAEVConfigHelper.from_configuration_object(
            ConfigLoader().to_daemon_config()
        )
        intercept_dump_argument(self.config.get_config_obj())
        with open(ICON_PATH, "rb") as icon_file:
            icon_bytes = icon_file.read()
        self.helper = OpenAEVInjectorHelper(self.config, icon_bytes)
        self.executor = C2Executor(logger=self.helper.injector_logger)

    @staticmethod
    def _first(value, default):
        if isinstance(value, list):
            value = value[0] if value else None
        return value if value not in (None, "") else default

    def process_message(self, data: Dict) -> None:
        start = time.time()
        inject_id = DataHelpers.get_inject_id(data)
        self.helper.api.inject.execution_reception(
            inject_id=inject_id, data={"tracking_total_count": 1}
        )

        try:
            content = DataHelpers.get_content(data)
            listener_url = content.get("listener_url")
            if not listener_url:
                raise ValueError("A C2 listener URL is required")

            result = self.executor.beacon(
                listener_url=listener_url,
                beacon_count=int(self._first(content.get("beacon_count"), 10)),
                interval_seconds=float(self._first(content.get("interval_seconds"), 5)),
                jitter_percent=float(self._first(content.get("jitter_percent"), 20)),
            )

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
        self.helper.injector_logger.info("Starting C2 Emulation injector...")
        self.helper.listen(message_callback=self.process_message)


if __name__ == "__main__":
    OpenAEVC2().start()
