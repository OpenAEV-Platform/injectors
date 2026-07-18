import time
from typing import Dict

from injector_common.data_helpers import DataHelpers
from injector_common.dump_config import intercept_dump_argument
from pyoaev.helpers import OpenAEVConfigHelper, OpenAEVInjectorHelper

from teams.client.graph_auth import GraphTokenProvider
from teams.client.teams_client import ExecutionResult, TeamsClient
from teams.configuration.config_loader import ConfigLoader
from teams.contracts_teams import (
    CONTRACT_ID,
    KEY_CHANNEL_ID,
    KEY_CHAT_ID,
    KEY_TARGET_TYPE,
    KEY_TEAM_ID,
    TARGET_CHANNEL,
    TARGET_CHAT,
)
from teams.helpers.teams_helper import TeamsPayloadBuilder


class OpenAEVTeamsInjector:

    def __init__(self):
        self.raw_config = ConfigLoader()
        self.config = OpenAEVConfigHelper.from_configuration_object(
            self.raw_config.to_daemon_config()
        )
        intercept_dump_argument(self.config.get_config_obj())
        with open("teams/img/icon-teams.png", "rb") as icon_file:
            icon_bytes = icon_file.read()
        self.helper = OpenAEVInjectorHelper(self.config, icon_bytes)

        teams_config = self.raw_config.teams
        timeout = teams_config.request_timeout_seconds
        token_provider = GraphTokenProvider(
            tenant_id=teams_config.tenant_id,
            client_id=teams_config.client_id,
            client_secret=teams_config.client_secret.get_secret_value(),
            refresh_token=teams_config.refresh_token.get_secret_value(),
            authority_base_url=teams_config.authority_base_url,
            scope=teams_config.scope,
            timeout=timeout,
        )
        self.client = TeamsClient(
            token_provider=token_provider,
            graph_base_url=teams_config.graph_base_url,
            timeout=timeout,
        )

    def execute(self, data: Dict) -> ExecutionResult:
        inject_contract = DataHelpers.get_injector_contract_id(data)
        if inject_contract != CONTRACT_ID:
            raise ValueError("Unsupported contract for Teams injector")

        content = DataHelpers.get_content(data)
        target_type = (content.get(KEY_TARGET_TYPE) or TARGET_CHANNEL).lower()
        body = TeamsPayloadBuilder.build(content)

        if target_type == TARGET_CHAT:
            chat_id = (content.get(KEY_CHAT_ID) or "").strip()
            if not chat_id:
                raise ValueError("A chat id is required to post a Teams chat message")
            return self.client.post_chat_message(chat_id, body)

        team_id = (content.get(KEY_TEAM_ID) or "").strip()
        channel_id = (content.get(KEY_CHANNEL_ID) or "").strip()
        if not team_id or not channel_id:
            raise ValueError(
                "A team id and a channel id are required to post a Teams channel message"
            )
        return self.client.post_channel_message(team_id, channel_id, body)

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
    injector = OpenAEVTeamsInjector()
    injector.start()
