"""Signature lifecycle helper for the Email injector."""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any

from ioc_finder import find_iocs
from pyoaev.signatures import (
    ExtraSignatureData,
    SignatureManager,
)
from pyoaev.signatures.models import ExecutionDetails, ExecutionSignature
from pyoaev.signatures.types import SignatureTypes

from injector_common.targets import TargetMeta

logger = logging.getLogger(__name__)


def _hash_bytes(data: bytes, algorithm: str) -> str:
    """Hash binary data using the specified algorithm."""
    return hashlib.new(algorithm, data).hexdigest()


def _hash_str(data: str, algorithm: str) -> str:
    """Hash a string using the specified algorithm."""
    return _hash_bytes(data.encode(), algorithm)


class EmailSignatureService:
    """Wraps the pyoaev SignatureManager for the email injector.

    Email is not a network/cloud scanner — there are no target IPs or cloud
    accounts.  The service builds minimal execution signatures (start/end
    timing only).  Email address, URL hash, and attachment hash indicators
    are delivered via the contract output (``execution_output_structured``)
    rather than through the signature payload.
    """

    def __init__(self, signature_manager: SignatureManager) -> None:
        self._sm = signature_manager

    # -- pre-execution -------------------------------------------------------

    @staticmethod
    def build_execution_details() -> ExecutionDetails:
        """Create an ``ExecutionDetails`` that records *now* as start time."""
        return ExecutionDetails()

    @staticmethod
    def build_execution_signature() -> ExecutionSignature:
        """Return a minimal execution signature with only a start timestamp."""
        return ExecutionSignature(
            start_time=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )

    # -- post-execution ------------------------------------------------------

    def post_execution_updates(
        self,
        execution_details: ExecutionDetails,
        execution_signature: ExecutionSignature,
        *,
        success: bool,
    ) -> None:
        """Update execution details and signature after the email send."""
        tool_output: dict[str, Any] = (
            {"error_info": None} if success else {"error_info": {"exit_code": 1}}
        )
        self._sm.post_execution_updates(
            execution_details, execution_signature, tool_output
        )

    # -- output structured ---------------------------------------------------

    @staticmethod
    def build_email_signatures(
        payload: dict,
        attachments: list[tuple[str, bytes]] | None = None,
        *,
        hash_algorithm: str,
    ) -> dict[str, list[str]]:
        """Extract email indicators from the payload.

        Returns a dict of signature-type → list-of-values suitable for
        inclusion in ``execution_output_structured["expectation_signatures"]``.

        Signature types produced:
        - ``source_email``: from address + mail_from (envelope sender) if different
        - ``target_email``: to + cc + bcc + reply-to addresses
        - ``url_hash``: hashes of URLs found in the plain-text and HTML bodies
        - ``file_hash``: hashes of attachment file contents
        - ``email_custom_header``: custom header name:value pairs (plain text)
        """
        signatures: dict[str, list[str]] = {}

        # Sender signatures
        sender_emails: list[str] = []
        from_addr = payload.get("from", "")
        if from_addr:
            sender_emails.append(from_addr)
        mail_from = payload.get("mail_from", "")
        if mail_from and mail_from != from_addr:
            sender_emails.append(mail_from)
        if sender_emails:
            signatures[SignatureTypes.SIG_TYPE_SOURCE_EMAIL.value] = sender_emails

        # Recipient signatures
        recipient_emails: list[str] = []
        to_addr = payload.get("to", "")
        if to_addr:
            recipient_emails.append(to_addr)
        for cc in payload.get("cc", []):
            if cc:
                recipient_emails.append(cc)
        for bcc in payload.get("bcc", []):
            if bcc:
                recipient_emails.append(bcc)
        reply_to = payload.get("reply_to")
        if reply_to:
            recipient_emails.append(reply_to)
        if recipient_emails:
            signatures[SignatureTypes.SIG_TYPE_TARGET_EMAIL.value] = recipient_emails

        # URL hash signatures from body (plain text and HTML)
        url_hashes = EmailSignatureService._extract_url_hashes(
            [payload.get("body", ""), payload.get("body_html", "")],
            hash_algorithm,
        )
        if url_hashes:
            signatures[SignatureTypes.SIG_TYPE_URL_HASH.value] = url_hashes

        # Attachment hash signatures
        if attachments:
            attachment_hashes = [
                _hash_bytes(content, hash_algorithm) for _, content in attachments
            ]
            signatures[SignatureTypes.SIG_TYPE_FILE_HASH.value] = attachment_hashes

        # Custom header signatures (stored as plain "name: value" strings)
        custom_headers = payload.get("custom_headers", [])
        if custom_headers:
            signatures[SignatureTypes.SIG_TYPE_EMAIL_CUSTOM_HEADER.value] = [
                f"{name}: {value}" for name, value in custom_headers
            ]

        return signatures

    @staticmethod
    def _extract_url_hashes(bodies: str | list[str], algorithm: str) -> list[str]:
        """Extract URLs from one or more text/HTML bodies and hash them.

        URLs are deduplicated across all bodies while preserving their first
        occurrence order.
        """
        if isinstance(bodies, str):
            bodies = [bodies]
        seen: set[str] = set()
        hashes: list[str] = []
        for body in bodies:
            if not body:
                continue
            for url in find_iocs(body).get("urls", []):
                url_hash = _hash_str(url, algorithm)
                if url_hash not in seen:
                    seen.add(url_hash)
                    hashes.append(url_hash)
        return hashes

    # -- payload & send ------------------------------------------------------

    def send_signatures(
        self,
        inject_id: str,
        execution_details: ExecutionDetails,
        execution_signature: ExecutionSignature,
    ) -> None:
        """Build payload and ship it. Email indicators go via output_structured."""
        target_meta = TargetMeta()
        extra = ExtraSignatureData()

        sig_payload = self._sm.build_payload(
            execution_signatures=[execution_signature],
            targets_meta=[target_meta],
            expectation_types=["DETECTION"],
            extra_signatures=extra,
        )
        self._sm.send_signatures(inject_id, execution_details, signatures=sig_payload)
