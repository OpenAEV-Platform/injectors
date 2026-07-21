"""Signature lifecycle helper for the Email-SMTP injector."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from pyoaev.signatures import (
    ExtraSignatureData,
    SignatureManager,
)
from pyoaev.signatures.models import ExecutionDetails, ExecutionSignature

from injector_common.targets import TargetMeta

logger = logging.getLogger(__name__)

# Signature type constants for email indicators
SENDER_EMAIL = "sender_email"
RECIPIENT_EMAIL = "recipient_email"
REPLY_TO_EMAIL = "reply_to_email"


class EmailSignatureService:
    """Wraps the pyoaev SignatureManager for the email-smtp injector.

    Email is not a network/cloud scanner — there are no target IPs or cloud
    accounts.  The service builds minimal execution signatures (start/end
    timing only).  Email address indicators are delivered via the contract
    output (``execution_output_structured``) rather than through the
    signature payload.
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
    def build_email_signatures(payload: dict) -> dict[str, list[str]]:
        """Extract email address indicators from the payload.

        Returns a dict of signature-type → list-of-values suitable for
        inclusion in ``execution_output_structured["expectation_signatures"]``.

        Signature types produced:
        - ``sender_email``: from address + mail_from (envelope sender) if different
        - ``recipient_email``: to + cc + bcc addresses
        - ``reply_to_email``: reply-to address (only when present)
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
            signatures[SENDER_EMAIL] = sender_emails

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
        if recipient_emails:
            signatures[RECIPIENT_EMAIL] = recipient_emails

        # Reply-To signature
        reply_to = payload.get("reply_to")
        if reply_to:
            signatures[REPLY_TO_EMAIL] = [reply_to]

        return signatures

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
