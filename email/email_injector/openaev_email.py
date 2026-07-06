import time
from typing import Dict

from injector_common.data_helpers import DataHelpers
from injector_common.dump_config import intercept_dump_argument
from pyoaev.helpers import OpenAEVConfigHelper, OpenAEVInjectorHelper

from email_injector.client.email_client import EmailClient, ExecutionResult
from email_injector.configuration.config_loader import ConfigLoader
from email_injector.contracts_email import CONTRACT_ID
from email_injector.helpers.email_helper import EmailPayloadBuilder


class OpenAEVEmailInjector:

    def __init__(self):
        self.config = OpenAEVConfigHelper.from_configuration_object(
            ConfigLoader().to_daemon_config()
        )
        intercept_dump_argument(self.config.get_config_obj())
        # Note: We'll need to create this icon later or use a placeholder
        try:
            with open("email_injector/img/icon-email.png", "rb") as icon_file:
                icon_bytes = icon_file.read()
        except FileNotFoundError:
            icon_bytes = b""  # Placeholder if icon is missing

        self.helper = OpenAEVInjectorHelper(self.config, icon_bytes)
        pass

    def execute(self, data: Dict) -> ExecutionResult:
        # Contract execution
        inject_contract = DataHelpers.get_injector_contract_id(data)
        if inject_contract != CONTRACT_ID:
            raise ValueError("Unsupported contract for Email injector")

        content = DataHelpers.get_content(data)
        payload = EmailPayloadBuilder.build(content)

        return EmailClient.send_email(
            smtp_hostname=self.config.get_conf("smtp_hostname", required=True),
            smtp_port=int(self.config.get_conf("smtp_port", default=587)),
            smtp_use_tls=self.config.get_conf("smtp_use_tls", default=False),
            smtp_username=self.config.get_conf("smtp_username", default=None),
            smtp_password=self.config.get_conf("smtp_password", default=None),
            from_email=payload["from"],
            to_email=payload["to"],
            subject=payload["subject"],
            body=payload["body"],
        )

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
    injector = OpenAEVEmailInjector()
    injector.start()
