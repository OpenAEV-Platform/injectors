import json
import time
from typing import Dict

from exfiltration_injector.configuration.config_loader import ConfigLoader
from exfiltration_injector.contracts_exfiltration import (
    CLOUD_EXFIL_CONTRACT,
    DNS_EXFIL_CONTRACT,
    HTTPS_EXFIL_CONTRACT,
    MAX_SIZE_KB,
    MIN_SIZE_KB,
)
from exfiltration_injector.helpers.exfiltration_executor import ExfiltrationExecutor
from pyoaev.helpers import OpenAEVConfigHelper, OpenAEVInjectorHelper

from injector_common.data_helpers import DataHelpers
from injector_common.dump_config import intercept_dump_argument

ICON_PATH = "exfiltration_injector/img/icon-exfiltration.png"


class OpenAEVExfiltration:
    def __init__(self):
        self.config = OpenAEVConfigHelper.from_configuration_object(
            ConfigLoader().to_daemon_config()
        )
        intercept_dump_argument(self.config.get_config_obj())
        with open(ICON_PATH, "rb") as icon_file:
            icon_bytes = icon_file.read()
        self.helper = OpenAEVInjectorHelper(self.config, icon_bytes)
        self.executor = ExfiltrationExecutor(logger=self.helper.injector_logger)

    @staticmethod
    def _size(content: Dict) -> int:
        raw = content.get("size_kb")
        if isinstance(raw, list):
            raw = raw[0] if raw else None
        try:
            size_kb = int(raw)
        except (TypeError, ValueError):
            size_kb = 64
        # Clamp to the supported contract range so an out-of-range value cannot
        # drive an oversized os.urandom allocation in the container.
        return max(MIN_SIZE_KB, min(size_kb, MAX_SIZE_KB))

    @staticmethod
    def _required(content: Dict, key: str) -> str:
        raw = content.get(key)
        if isinstance(raw, list):
            raw = raw[0] if raw else None
        if raw is None or (isinstance(raw, str) and not raw.strip()):
            raise ValueError(f"Missing required field: {key}")
        return raw

    def _dispatch(self, contract_id: str, content: Dict):
        size_kb = self._size(content)
        if contract_id == DNS_EXFIL_CONTRACT:
            return self.executor.exfiltrate_dns(
                self._required(content, "dns_domain"), size_kb
            )
        if contract_id == HTTPS_EXFIL_CONTRACT:
            return self.executor.exfiltrate_https(
                self._required(content, "https_url"), size_kb
            )
        if contract_id == CLOUD_EXFIL_CONTRACT:
            return self.executor.exfiltrate_cloud(
                self._required(content, "cloud_url"), size_kb
            )
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
        self.helper.injector_logger.info("Starting Data Exfiltration injector...")
        self.helper.listen(message_callback=self.process_message)


if __name__ == "__main__":
    OpenAEVExfiltration().start()
