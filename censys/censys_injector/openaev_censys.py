import json
import time
from typing import Dict

from injector_common.data_helpers import DataHelpers
from injector_common.dump_config import intercept_dump_argument
from pyoaev.helpers import OpenAEVConfigHelper, OpenAEVInjectorHelper

from censys_injector.client.censys_client import CensysClient
from censys_injector.configuration.config_loader import ConfigLoader
from censys_injector.contracts_censys import (
    CERT_SEARCH_CONTRACT,
    HOST_SEARCH_CONTRACT,
)

ICON_PATH = "censys_injector/img/icon-censys.png"


class OpenAEVCensys:
    def __init__(self):
        self.config_loader = ConfigLoader()
        self.config = OpenAEVConfigHelper.from_configuration_object(
            self.config_loader.to_daemon_config()
        )
        intercept_dump_argument(self.config.get_config_obj())
        with open(ICON_PATH, "rb") as icon_file:
            icon_bytes = icon_file.read()
        self.helper = OpenAEVInjectorHelper(self.config, icon_bytes)
        censys_conf = self.config_loader.censys
        self.client = CensysClient(
            api_id=censys_conf.api_id.get_secret_value(),
            api_secret=censys_conf.api_secret.get_secret_value(),
            base_url=censys_conf.base_url,
            per_page=censys_conf.per_page,
            logger=self.helper.injector_logger,
        )

    def process_message(self, data: Dict) -> None:
        start = time.time()
        inject_id = DataHelpers.get_inject_id(data)
        self.helper.api.inject.execution_reception(
            inject_id=inject_id, data={"tracking_total_count": 1}
        )

        try:
            contract_id = DataHelpers.get_injector_contract_id(data)
            content = DataHelpers.get_content(data)
            query = content.get("query")
            if not query:
                raise ValueError("A Censys search query is required")

            if contract_id == HOST_SEARCH_CONTRACT:
                result = self.client.search_hosts(query)
            elif contract_id == CERT_SEARCH_CONTRACT:
                result = self.client.search_certificates(query)
            else:
                raise ValueError(f"Unsupported contract id: {contract_id}")

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
        self.helper.injector_logger.info("Starting Censys injector...")
        self.helper.listen(message_callback=self.process_message)


if __name__ == "__main__":
    OpenAEVCensys().start()
