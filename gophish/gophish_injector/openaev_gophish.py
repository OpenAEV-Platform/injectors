import json
import time
from typing import Dict

from gophish_injector.client.gophish_client import GophishClient
from gophish_injector.configuration.config_loader import ConfigLoader
from pyoaev.helpers import OpenAEVConfigHelper, OpenAEVInjectorHelper

from injector_common.data_helpers import DataHelpers
from injector_common.dump_config import intercept_dump_argument

ICON_PATH = "gophish_injector/img/icon-gophish.png"


class OpenAEVGophish:
    def __init__(self):
        self.config_loader = ConfigLoader()
        self.config = OpenAEVConfigHelper.from_configuration_object(
            self.config_loader.to_daemon_config()
        )
        intercept_dump_argument(self.config.get_config_obj())
        with open(ICON_PATH, "rb") as icon_file:
            icon_bytes = icon_file.read()
        self.helper = OpenAEVInjectorHelper(self.config, icon_bytes)
        gophish_conf = self.config_loader.gophish
        self.client = GophishClient(
            base_url=gophish_conf.base_url,
            api_key=gophish_conf.api_key.get_secret_value(),
            verify_tls=gophish_conf.verify_tls,
            logger=self.helper.injector_logger,
        )

    def process_message(self, data: Dict) -> None:
        start = time.time()
        inject_id = DataHelpers.get_inject_id(data)
        self.helper.api.inject.execution_reception(
            inject_id=inject_id, data={"tracking_total_count": 1}
        )

        try:
            content = DataHelpers.get_content(data)
            result = self.client.create_campaign(
                name=content.get("campaign_name"),
                template_name=content.get("template_name"),
                page_name=content.get("page_name"),
                smtp_name=content.get("smtp_name"),
                group_name=content.get("group_name"),
                url=content.get("url"),
            )

            callback_data = {
                "execution_message": result.message,
                "execution_status": "SUCCESS" if result.success else "ERROR",
                "execution_duration": int(time.time() - start),
                "execution_action": "complete",
            }
            if result.success:
                callback_data["execution_output_structured"] = json.dumps(
                    {
                        "campaign_id": [str(result.campaign_id)],
                        "stats": [json.dumps(result.stats)],
                    }
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
        self.helper.injector_logger.info("Starting Gophish injector...")
        self.helper.listen(message_callback=self.process_message)


if __name__ == "__main__":
    OpenAEVGophish().start()
