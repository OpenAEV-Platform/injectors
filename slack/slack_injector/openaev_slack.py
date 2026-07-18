import time
from typing import Dict

from pyoaev.helpers import OpenAEVConfigHelper, OpenAEVInjectorHelper
from slack_injector.client.slack_client import ExecutionResult, SlackClient
from slack_injector.configuration.config_loader import ConfigLoader
from slack_injector.contracts_slack import CONTRACT_ID, KEY_CHANNEL
from slack_injector.helpers.slack_helper import SlackPayloadBuilder

from injector_common.data_helpers import DataHelpers
from injector_common.dump_config import intercept_dump_argument


class OpenAEVSlackInjector:

    def __init__(self):
        self.raw_config = ConfigLoader()
        self.config = OpenAEVConfigHelper.from_configuration_object(
            self.raw_config.to_daemon_config()
        )
        intercept_dump_argument(self.config.get_config_obj())
        with open("slack_injector/img/icon-slack.png", "rb") as icon_file:
            icon_bytes = icon_file.read()
        self.helper = OpenAEVInjectorHelper(self.config, icon_bytes)

        slack_config = self.raw_config.slack
        self.client = SlackClient(
            bot_token=slack_config.bot_token.get_secret_value(),
            base_url=slack_config.base_url,
            timeout=slack_config.request_timeout_seconds,
        )

    def execute(self, data: Dict) -> ExecutionResult:
        inject_contract = DataHelpers.get_injector_contract_id(data)
        if inject_contract != CONTRACT_ID:
            raise ValueError("Unsupported contract for Slack injector")

        content = DataHelpers.get_content(data)
        channel = (content.get(KEY_CHANNEL) or "").strip()
        if not channel:
            raise ValueError("A channel or user id is required to post a Slack message")

        payload = SlackPayloadBuilder.build(channel, content)
        return self.client.post_message(payload)

    def process_message(self, data: Dict) -> None:
        start = time.time()
        inject_id = DataHelpers.get_inject_id(data)

        # Notify API of reception and expected number of operations
        self.helper.api.inject.execution_reception(
            inject_id=inject_id, data={"tracking_total_count": 1}
        )

        try:
            result = self.execute(data)
            callback_data = {
                "execution_message": result.message,
                "execution_status": "SUCCESS" if result.success else "ERROR",
                "execution_duration": int(time.time() - start),
                "execution_action": "complete",
            }
            self.helper.api.inject.execution_callback(
                inject_id=inject_id, data=callback_data
            )
        except Exception as e:
            callback_data = {
                "execution_message": str(e),
                "execution_status": "ERROR",
                "execution_duration": int(time.time() - start),
                "execution_action": "complete",
            }
            self.helper.api.inject.execution_callback(
                inject_id=inject_id, data=callback_data
            )

    def start(self):
        self.helper.listen(message_callback=self.process_message)


if __name__ == "__main__":
    injector = OpenAEVSlackInjector()
    injector.start()
