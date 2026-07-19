import time
from typing import Dict, List, Tuple

from injector_common.data_helpers import DataHelpers
from injector_common.dump_config import intercept_dump_argument
from pyoaev.helpers import OpenAEVConfigHelper, OpenAEVInjectorHelper

from email_gws_injector.client.gmail_client import ExecutionResult, GmailClient
from email_gws_injector.configuration.config_loader import ConfigLoader
from email_gws_injector.contracts_email_gws import CONTRACT_ID
from email_gws_injector.helpers.email_helper import EmailMessageBuilder


class OpenAEVEmailGWSInjector:

    def __init__(self):
        self.raw_config = ConfigLoader()
        self.config = OpenAEVConfigHelper.from_configuration_object(
            self.raw_config.to_daemon_config()
        )
        intercept_dump_argument(self.config.get_config_obj())
        with open(
            "email_gws_injector/img/icon-email-google-workspace.png", "rb"
        ) as icon_file:
            icon_bytes = icon_file.read()
        self.helper = OpenAEVInjectorHelper(self.config, icon_bytes)

        gws_config = self.raw_config.gws
        self.client = GmailClient(
            service_account_json=gws_config.service_account_json.get_secret_value(),
            gmail_base_url=gws_config.gmail_base_url,
            timeout=gws_config.request_timeout_seconds,
        )

    def execute(self, data: Dict) -> ExecutionResult:
        inject_contract = DataHelpers.get_injector_contract_id(data)
        if inject_contract != CONTRACT_ID:
            raise ValueError(
                "Unsupported contract for Email (Google Workspace) injector"
            )

        content = DataHelpers.get_content(data)
        attachments = self._extract_attachments(data)
        payload = EmailMessageBuilder.build(content, attachments)
        return self.client.send_message(
            sender=payload["sender"],
            raw_message=payload["raw"],
        )

    def _extract_attachments(self, data: Dict) -> List[Tuple[str, bytes]]:
        documents = data.get("injection", {}).get("inject_documents") or []
        attachments = [doc for doc in documents if doc.get("document_attached") is True]
        if not attachments:
            return []

        extracted: List[Tuple[str, bytes]] = []
        for attachment in attachments:
            attachment_name = attachment.get("document_name")
            if not attachment_name:
                raise ValueError("Attachment is missing a document_name")
            document_id = attachment.get("document_id")
            if not document_id:
                raise ValueError(
                    f"Attachment {attachment_name} is missing a document_id"
                )
            response = self.helper.api.document.download(document_id)
            status_code = (
                response.get("status_code")
                if isinstance(response, dict)
                else getattr(response, "status_code", None)
            )
            if status_code != 200:
                raise ValueError(f"Attachment download failed for {attachment_name}")
            file_content = (
                response.get("content")
                if isinstance(response, dict)
                else getattr(response, "content", None)
            )
            if file_content is None:
                raise ValueError(f"Attachment content missing for {attachment_name}")
            if isinstance(file_content, str):
                file_content = file_content.encode()
            if not isinstance(file_content, (bytes, bytearray)):
                raise ValueError(
                    f"Attachment content is not binary for {attachment_name}"
                )
            extracted.append((attachment_name, bytes(file_content)))

        return extracted

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
    injector = OpenAEVEmailGWSInjector()
    injector.start()
