import time
from typing import Dict

from pyoaev.helpers import OpenAEVConfigHelper, OpenAEVInjectorHelper

from injector_common.data_helpers import DataHelpers
from injector_common.dump_config import intercept_dump_argument
from teams.client.teams_client import ExecutionResult, TeamsClient
from teams.configuration.config_loader import ConfigLoader
from teams.contracts_teams import (
    CONTRACT_ID,
)
from teams.helpers.teams_helper import TeamsPayloadBuilder


class OpenAEVTeamsInjector:

    def __init__(self):
        self.config = OpenAEVConfigHelper.from_configuration_object(
            ConfigLoader().to_daemon_config()
        )
        intercept_dump_argument(self.config.get_config_obj())
        with open("teams/img/icon-teams.png", "rb") as icon_file:
            icon_bytes = icon_file.read()
        self.helper = OpenAEVInjectorHelper(self.config, icon_bytes)

    def execute(self, data: Dict) -> ExecutionResult:
        # Contract execution
        inject_contract = DataHelpers.get_injector_contract_id(data)
        if inject_contract != CONTRACT_ID:
            raise ValueError("Unsupported contract for Teams injector")

        content = DataHelpers.get_content(data)
        payload = TeamsPayloadBuilder.build(content)

        return TeamsClient.post_message(content["uri"], payload)

    def process_message(self, data: Dict) -> None:
        start = time.time()
        inject_id = DataHelpers.get_inject_id(data)

        # Notify API of reception and expected number of operations
        self.helper.api.inject.execution_reception(
            inject_id=inject_id, data={"tracking_total_count": 1}
        )

        # Execute inject
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
    injector = OpenAEVTeamsInjector()
    injector.start()
