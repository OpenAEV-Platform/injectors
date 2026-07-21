import json
import time
from typing import Dict, List, Tuple

from email_smtp.contracts import EmailContractId
from email_smtp.models import ConfigLoader
from email_smtp.models.exceptions import (
    AttachmentDownloadError,
    InvalidContractError,
    MissingRequiredFieldError,
)
from email_smtp.services import EmailClient, EmailPayloadBuilder, ExecutionResult
from email_smtp.services.signature_service import EmailSignatureService
from pyoaev.helpers import OpenAEVInjectorHelper
from pyoaev.signatures import SignatureManager

from injector_common.data_helpers import DataHelpers

LOG_PREFIX = "[EMAIL_SMTP_INJECTOR]"


class EmailSmtpInjector:
    def __init__(self, config: ConfigLoader, helper: OpenAEVInjectorHelper):
        """Initialize the Injector with necessary configurations."""
        self.config = config
        self.helper = helper
        self.signature_service = EmailSignatureService(
            SignatureManager(self.helper.api)
        )
        self.helper.injector_logger.info(f"{LOG_PREFIX} - Email injector initialized")

    def execute(self, data: Dict) -> ExecutionResult:
        inject_contract = DataHelpers.get_injector_contract_id(data)
        if inject_contract != EmailContractId.CRAFT_EMAIL:
            raise InvalidContractError("Unsupported contract for Email injector")

        content = DataHelpers.get_content(data)
        payload = EmailPayloadBuilder.build(content)
        attachments = self._extract_attachments(data)
        self.helper.injector_logger.info(
            f"{LOG_PREFIX} - Crafting email",
            {
                "to": payload["to"],
                "cc_count": len(payload["cc"]),
                "bcc_count": len(payload["bcc"]),
                "attachments_count": len(attachments),
                "subject": payload["subject"],
                "smtp_host": payload["smtp_hostname"],
                "smtp_port": payload["smtp_port"],
                "tls": payload["smtp_use_tls"],
            },
        )

        result = EmailClient.send_email(
            smtp_hostname=payload["smtp_hostname"],
            smtp_port=payload["smtp_port"],
            smtp_use_tls=payload["smtp_use_tls"],
            smtp_username=payload["smtp_username"],
            smtp_password=payload["smtp_password"],
            from_email=payload["from"],
            mail_from=payload["mail_from"],
            reply_to=payload["reply_to"],
            to_email=payload["to"],
            cc_emails=payload["cc"],
            bcc_emails=payload["bcc"],
            subject=payload["subject"],
            body=payload["body"],
            custom_headers=payload["custom_headers"],
            attachments=attachments,
        )
        if result.success:
            self.helper.injector_logger.info(
                f"{LOG_PREFIX} - Email crafted successfully",
                {"to": payload["to"]},
            )
        else:
            self.helper.injector_logger.error(
                f"{LOG_PREFIX} - Email crafting failed",
                {"error": result.message},
            )
        return result

    def _extract_attachments(self, data: Dict) -> List[Tuple[str, bytes]]:
        documents = data.get("injection", {}).get("inject_documents", [])
        attachments = [doc for doc in documents if doc.get("document_attached") is True]
        if not attachments:
            return []

        extracted_attachments: List[Tuple[str, bytes]] = []
        for attachment in attachments:
            attachment_name = attachment.get("document_name")
            if not attachment_name:
                raise MissingRequiredFieldError("Attachment is missing a document_name")
            document_id = attachment.get("document_id")
            if not document_id:
                raise MissingRequiredFieldError(
                    f"Attachment is missing a document_id: {attachment_name}"
                )
            response = self.helper.api.document.download(document_id)
            status_code = (
                response.get("status_code")
                if isinstance(response, dict)
                else getattr(response, "status_code", None)
            )
            if status_code != 200:
                raise AttachmentDownloadError(
                    f"Attachment download failed for {attachment_name}"
                )
            content = (
                response.get("content")
                if isinstance(response, dict)
                else getattr(response, "content", None)
            )
            if content is None:
                raise AttachmentDownloadError(
                    f"Attachment content missing for {attachment_name}"
                )
            if isinstance(content, str):
                content = content.encode()
            if not isinstance(content, (bytes, bytearray)):
                raise AttachmentDownloadError(
                    f"Attachment content is not binary for {attachment_name}"
                )
            extracted_attachments.append((attachment_name, bytes(content)))

        return extracted_attachments

    def process_message(self, data: Dict) -> None:
        start = time.time()
        inject_id = DataHelpers.get_inject_id(data)
        self.helper.injector_logger.info(
            f"{LOG_PREFIX} - Received email inject message",
            {"inject_id": inject_id},
        )

        self.helper.api.inject.execution_reception(
            inject_id=inject_id, data={"tracking_total_count": 1}
        )

        execution_details = self.signature_service.build_execution_details()
        execution_signature = self.signature_service.build_execution_signature()

        try:
            result = self.execute(data)

            output_structured = self._build_output_structured(data)
            callback_data = {
                "execution_message": result.message,
                "execution_output_structured": json.dumps(output_structured),
                "execution_status": "SUCCESS" if result.success else "ERROR",
                "execution_duration": int(time.time() - start),
                "execution_action": "complete",
            }

            self.helper.api.inject.execution_callback(
                inject_id=inject_id, data=callback_data
            )
            if result.success:
                self.helper.injector_logger.info(
                    f"{LOG_PREFIX} - Inject completed successfully",
                    {"inject_id": inject_id},
                )
            else:
                self.helper.injector_logger.error(
                    f"{LOG_PREFIX} - Inject completed with error",
                    {"inject_id": inject_id, "error": result.message},
                )

            self.signature_service.post_execution_updates(
                execution_details, execution_signature, success=result.success
            )

        except Exception as err:
            callback_data = {
                "execution_message": str(err),
                "execution_status": "ERROR",
                "execution_duration": int(time.time() - start),
                "execution_action": "complete",
            }
            self.helper.api.inject.execution_callback(
                inject_id=inject_id, data=callback_data
            )
            self.helper.injector_logger.error(
                f"{LOG_PREFIX} - Unexpected error while processing inject",
                {"inject_id": inject_id, "error": str(err)},
            )

            self.signature_service.post_execution_updates(
                execution_details, execution_signature, success=False
            )

        self._send_signatures(inject_id, execution_details, execution_signature)

    @staticmethod
    def _build_output_structured(data: Dict) -> Dict:
        """Build the contract output structure with the recipient email address."""
        content = DataHelpers.get_content(data)
        to_address = content.get("to", "")
        return {"expectation_signatures": [to_address]} if to_address else {}

    def _send_signatures(
        self,
        inject_id: str,
        execution_details,
        execution_signature,
    ) -> None:
        """Send signature data to the platform. Errors are logged, never raised."""
        try:
            self.signature_service.send_signatures(
                inject_id, execution_details, execution_signature
            )
            self.helper.injector_logger.info(
                f"{LOG_PREFIX} - Signatures sent",
                {"inject_id": inject_id},
            )
        except Exception as err:
            self.helper.injector_logger.error(
                f"{LOG_PREFIX} - Failed to send signatures",
                {"inject_id": inject_id, "error": str(err)},
            )

    def start(self) -> None:
        self.helper.injector_logger.info(
            f"{LOG_PREFIX} - Starting email injector listener"
        )
        self.helper.listen(message_callback=self.process_message)
