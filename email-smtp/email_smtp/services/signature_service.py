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


class EmailSignatureService:
    """Wraps the pyoaev SignatureManager for the email-smtp injector.

    Email is not a network/cloud scanner — there are no target IPs or cloud
    accounts.  The service therefore builds minimal execution signatures
    (start/end timing only) and leaves extra-signature slots empty until
    concrete indicator types (address hashes, URL hashes, …) are wired in.
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

    # -- payload & send ------------------------------------------------------

    def send_signatures(
        self,
        inject_id: str,
        execution_details: ExecutionDetails,
        execution_signature: ExecutionSignature,
    ) -> None:
        """Build payload with empty extra signatures and ship it."""
        target_meta = TargetMeta()
        extra = ExtraSignatureData()

        payload = self._sm.build_payload(
            execution_signatures=[execution_signature],
            targets_meta=[target_meta],
            expectation_types=["DETECTION"],
            extra_signatures=extra,
        )
        self._sm.send_signatures(inject_id, execution_details, signatures=payload)
