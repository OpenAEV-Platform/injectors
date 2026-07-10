import time
from typing import Dict

from email_injector.client.email_client import EmailClient, ExecutionResult
from email_injector.configuration.config_loader import ConfigLoader
from email_injector.contracts_email import CONTRACT_ID
from email_injector.helpers.email_helper import EmailPayloadBuilder
from pyoaev.helpers import OpenAEVConfigHelper, OpenAEVInjectorHelper

from injector_common.data_helpers import DataHelpers
from injector_common.dump_config import intercept_dump_argument


class OpenAEVEmailInjector:

    def __init__(self):
        self.config = OpenAEVConfigHelper.from_configuration_object(
            ConfigLoader().to_daemon_config()
        )
        intercept_dump_argument(self.config.get_config_obj())
        try:
            with open("email_injector/img/icon-email.png", "rb") as icon_file:
                icon_bytes = icon_file.read()
        except FileNotFoundError:
            icon_bytes = b""

        self.helper = OpenAEVInjectorHelper(self.config, icon_bytes)
        self.helper.injector_logger.info("Email injector initialized")

    def execute(self, data: Dict) -> ExecutionResult:
        inject_contract = DataHelpers.get_injector_contract_id(data)
        if inject_contract != CONTRACT_ID:
            raise ValueError("Unsupported contract for Email injector")

        content = DataHelpers.get_content(data)
        payload = EmailPayloadBuilder.build(content)
        attachments = self._extract_attachments(data)
        self.helper.injector_logger.info(
            f"Crafting email (to={payload['to']}, cc_count={len(payload['cc'])}, bcc_count={len(payload['bcc'])}, attachments_count={len(attachments)}, subject={payload['subject']}, smtp_host={payload['smtp_hostname']}, smtp_port={payload['smtp_port']}, tls={payload['smtp_use_tls']})"
        )

        result = EmailClient.send_email(
            smtp_hostname=payload["smtp_hostname"],
            smtp_port=payload["smtp_port"],
            smtp_use_tls=payload["smtp_use_tls"],
            smtp_username=payload["smtp_username"],
            smtp_password=payload["smtp_password"],
            from_email=payload["from"],
            reply_to=payload["reply_to"],
            to_email=payload["to"],
            cc_emails=payload["cc"],
            bcc_emails=payload["bcc"],
            subject=payload["subject"],
            body=payload["body"],
            attachments=attachments,
        )
        if result.success:
            self.helper.injector_logger.info(
                f"Email crafted successfully (to={payload['to']})"
            )
        else:
            self.helper.injector_logger.error(
                f"Email crafting failed: {result.message}"
            )
        return result

    def _extract_attachments(self, data: Dict) -> list[tuple[str, bytes]]:
        documents = data.get("injection", {}).get("inject_documents", [])
        attachments = [doc for doc in documents if doc.get("document_attached") is True]
        if not attachments:
            return []

        extracted_attachments: list[tuple[str, bytes]] = []
        for attachment in attachments:
            attachment_name = attachment.get("document_name")
            if not attachment_name:
                raise ValueError("Attachment is missing a document_name")
            response = self.helper.api.document.download(attachment["document_id"])
            status_code = (
                response.get("status_code")
                if isinstance(response, dict)
                else getattr(response, "status_code", None)
            )
            if status_code != 200:
                raise ValueError(f"Attachment download failed for {attachment_name}")
            content = (
                response.get("content")
                if isinstance(response, dict)
                else getattr(response, "content", None)
            )
            if content is None:
                raise ValueError(f"Attachment content missing for {attachment_name}")
            if isinstance(content, str):
                content = content.encode()
            if not isinstance(content, (bytes, bytearray)):
                raise ValueError(
                    f"Attachment content is not binary for {attachment_name}"
                )
            extracted_attachments.append((attachment_name, bytes(content)))

        return extracted_attachments

    def process_message(self, data: Dict) -> None:
        start = time.time()
        inject_id = DataHelpers.get_inject_id(data)
        self.helper.injector_logger.info(
            f"Received email inject message (inject_id={inject_id})"
        )

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
            if result.success:
                self.helper.injector_logger.info(
                    f"Inject completed successfully (inject_id={inject_id})"
                )
            else:
                self.helper.injector_logger.error(
                    f"Inject completed with error (inject_id={inject_id}): {result.message}"
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
            self.helper.injector_logger.error(
                f"Unexpected error while processing inject (inject_id={inject_id}): {str(e)}"
            )

    def start(self):
        self.helper.injector_logger.info("Starting email injector listener")
        self.helper.listen(message_callback=self.process_message)


if __name__ == "__main__":
    injector = OpenAEVEmailInjector()
    injector.start()
