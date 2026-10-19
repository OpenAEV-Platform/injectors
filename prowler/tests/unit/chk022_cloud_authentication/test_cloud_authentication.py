"""Cloud authentication evidence, account checks, and scope fallbacks."""

# Fake secret values are compared on purpose, hence S105.
# ruff: noqa: D101, D102, D103, S105

from __future__ import annotations

import json
from typing import Any, ClassVar
from unittest.mock import Mock

import pytest
from pyoaev.credential import (  # type: ignore[import-untyped]
    CredentialErrorCode,
    CredentialResolutionError,
)

from prowler._core.cli_engine import (
    CommandResult,
    ExecutionSpecification,
    OutputSpecification,
)
from prowler.contracts import (
    BaseProwlerContract,
    ContractExecutionOutcome,
    ProwlerContracts,
    stable_contract_id,
)
from prowler.injector.authentication import (
    aws_account_from_role_arn,
    parse_authentication,
)

REFERENCE = "3f1c1e5e-0000-4000-8000-000000000001"
AUTHORISATION_CODE = "AUTHORISATION-CODE-CANARY"
ATTACHMENTS = {
    "credential_references": [REFERENCE],
    "authorisation_code": AUTHORISATION_CODE,
}
ACCOUNT = "123456789012"
OTHER_ACCOUNT = "210987654321"
# With a credential reference: the region comes from the credential.
AWS_FORM = {"aws_account_id": ACCOUNT}
AWS_ACCESS_KEY = {
    "type": "AWS_ACCESS_KEY",
    "value": {
        "aws_default_region": "us-east-1",
        "aws_access_key_id": "ACCESS-KEY-CANARY",
        "aws_secret_access_key": "SECRET-KEY-CANARY",
    },
}


def _assume_role(account: str) -> dict[str, Any]:
    return {
        "type": "AWS_ASSUME_ROLE",
        "value": {
            "aws_default_region": "us-east-2",
            "aws_role_arn": f"arn:aws:iam::{account}:role/audit",
            "aws_source_identity_type": "INSTANCE_DEFAULT",
        },
    }


def _aws_box(account: str = ACCOUNT, *, colored: bool = False) -> bytes:
    yellow, reset = ("\x1b[33m", "\x1b[0m") if colored else ("", "")
    return (
        "\x1b[1m-> Using the AWS credentials below:\x1b[0m\n"
        if colored
        else "-> Using the AWS credentials below:\n"
    ).encode() + (
        f"  · AWS-CLI Profile: {yellow}default{reset}\n"
        f"  · AWS Regions: {yellow}eu-west-1{reset}\n"
        f"  · AWS Account: {yellow}{account}{reset}\n"
        f"  · User Id: {yellow}AIDAEXAMPLE{reset}\n"
        f"  · Caller Identity ARN: {yellow}arn:aws:iam::{account}:user/audit{reset}\n"
        "\n"
        "Executing 12 checks, please wait...\n"
    ).encode()


# --- Credentials box parsing ----------------------------------------------


def test_aws_box_keeps_only_the_allowlisted_identity() -> None:
    authentication = parse_authentication(_aws_box())

    assert authentication is not None
    assert authentication.provider == "AWS"
    assert authentication.identity == (
        ("AWS Account", ACCOUNT),
        ("Caller Identity ARN", f"arn:aws:iam::{ACCOUNT}:user/audit"),
    )
    assert authentication.aws_account_id == ACCOUNT


def test_ansi_colors_are_ignored() -> None:
    assert parse_authentication(_aws_box(colored=True)) == parse_authentication(
        _aws_box()
    )


def test_azure_lines_with_several_pairs_are_split() -> None:
    stdout = (
        "-> Using the Azure credentials below:\n"
        "  · Azure Tenant Domain: contoso.example Azure Tenant ID: tenant-1\n"
        "  · Azure Region: AzureCloud\n"
        "  · Azure Subscriptions: ['sub-1']\n"
        "  · Azure Identity Type: Service Principal Azure Identity ID: app-1\n"
        "\n"
    ).encode()

    authentication = parse_authentication(stdout)

    assert authentication is not None
    assert authentication.identity == (
        ("Azure Tenant ID", "tenant-1"),
        ("Azure Subscriptions", "['sub-1']"),
        ("Azure Identity Type", "Service Principal"),
    )
    assert authentication.aws_account_id is None


def test_gcp_and_kubernetes_boxes() -> None:
    gcp = parse_authentication(
        b"-> Using the GCP credentials below:\n"
        b"  \xc2\xb7 GCP Account: audit@project.iam.gserviceaccount.com\n"
        b"  \xc2\xb7 GCP Project IDs: project-1\n"
    )
    kubernetes = parse_authentication(
        b"-> Using the Kubernetes credentials below:\n"
        b"  \xc2\xb7 Kubernetes Cluster: prod\n"
        b"  \xc2\xb7 User: admin\n"
        b"  \xc2\xb7 Namespaces: all\n"
    )

    assert gcp is not None and gcp.value("GCP Project IDs") == "project-1"
    assert kubernetes is not None and kubernetes.identity == (
        ("Kubernetes Cluster", "prod"),
        ("User", "admin"),
    )


@pytest.mark.parametrize(
    "stdout",
    (b"", b"Executing 12 checks\n", b"CRITICAL: AWS credentials not found\n"),
)
def test_no_box_means_no_authentication_evidence(stdout: bytes) -> None:
    assert parse_authentication(stdout) is None


@pytest.mark.parametrize(
    ("arn", "account"),
    (
        (f"arn:aws:iam::{ACCOUNT}:role/audit", ACCOUNT),
        (f"arn:aws-us-gov:iam::{ACCOUNT}:role/path/audit", ACCOUNT),
        (f"arn:aws:iam::{ACCOUNT}:user/audit", None),
        ("not-an-arn", None),
    ),
)
def test_account_of_a_role_arn(arn: str, account: str | None) -> None:
    assert aws_account_from_role_arn(arn) == account


# --- Injector flow ---------------------------------------------------------


def _specification() -> ExecutionSpecification:
    return ExecutionSpecification(
        executable="/fake/prowler",
        arguments=("/fake/prowler",),
        environment=(),
        working_directory=None,
        input_bytes=b"",
        output=OutputSpecification(),
        timeout_seconds=30.0,
        maximum_accepted_output_bytes=1024,
    )


class _Contract(BaseProwlerContract):
    contract_id: ClassVar[str] = str(stable_contract_id("aws"))
    external_id = "prowler:aws"
    route_name = "aws"
    provider = "aws"
    family = "base"
    label = "Authentication test"
    executed: ClassVar[list[Any]] = []
    stdout: ClassVar[bytes] = b""
    return_code: ClassVar[int] = 0

    def execute(self, config: Any, provider: Any) -> ContractExecutionOutcome:
        del config
        self.executed.append(provider)
        return ContractExecutionOutcome(
            command_result=CommandResult(
                specification=_specification(),
                stdout=self.stdout,
                return_code=self.return_code,
            )
        )


class _AzureContract(_Contract):
    contract_id: ClassVar[str] = str(stable_contract_id("azure"))
    external_id = "prowler:azure"
    route_name = "azure"
    provider = "azure"


def _process(
    helper: Mock,
    content: dict[str, str],
    *,
    attachments: object = None,
    stdout: bytes = b"",
    return_code: int = 0,
    contract: type[_Contract] = _Contract,
) -> list[dict[str, Any]]:
    """Process one job and return every callback payload, in order."""
    from prowler.injector import ProwlerInjector

    _Contract.executed = []
    contract.stdout = stdout
    contract.return_code = return_code
    injector = ProwlerInjector(Mock(), helper, registry=ProwlerContracts((contract,)))
    injector.process_message(
        {
            "injection": {
                "inject_id": "inject-test",
                "injector_contract_id": contract.contract_id,
                "inject_content": content,
            },
            "attachments": attachments,
        }
    )
    return [
        call.kwargs["data"]
        for call in helper.api.inject.execution_callback.call_args_list
    ]


def _helper(payload: dict[str, Any] | None = None) -> Mock:
    helper = Mock()
    helper.api.inject.resolve_attachment_secret.return_value = payload
    return helper


def test_authentication_is_traced_before_the_terminal_callback() -> None:
    helper = _helper(AWS_ACCESS_KEY)

    auth, terminal = _process(
        helper, AWS_FORM, attachments=ATTACHMENTS, stdout=_aws_box()
    )

    assert auth["execution_action"] == "prerequisite_check"
    assert auth["execution_status"] == "INFO"
    assert auth["execution_message"] == (
        f"Authenticated against AWS (AWS Account: {ACCOUNT}, Caller Identity ARN: "
        f"arn:aws:iam::{ACCOUNT}:user/audit) with credential reference "
        f"{REFERENCE} (AWS_ACCESS_KEY)"
    )
    assert terminal["execution_status"] == "SUCCESS"
    for payload in (auth, terminal):
        assert "CANARY" not in json.dumps(payload, default=str)
    info_messages = [call.args[0] for call in helper.injector_logger.info.mock_calls]
    assert "[PROWLER_INJECTOR] - Cloud authentication succeeded" in info_messages
    assert "[PROWLER_INJECTOR] - Referenced credential resolved" in info_messages


def test_legacy_path_names_the_inject_fields() -> None:
    legacy = {
        "aws_account_id": ACCOUNT,
        "aws_region": "eu-west-1",
        "aws_access_key_id": "K",
        "aws_secret_access_key": "S",
    }

    auth, _terminal = _process(_helper(), legacy, stdout=_aws_box())

    assert auth["execution_message"].endswith("with the inject credential fields")


def test_authentication_is_traced_even_when_the_scan_fails_afterwards() -> None:
    auth, terminal = _process(
        _helper(AWS_ACCESS_KEY),
        AWS_FORM,
        attachments=ATTACHMENTS,
        stdout=_aws_box(),
        return_code=1,
    )

    assert auth["execution_action"] == "prerequisite_check"
    assert terminal["execution_status"] == "ERROR"


def test_no_box_sends_no_authentication_trace() -> None:
    callbacks = _process(_helper(AWS_ACCESS_KEY), AWS_FORM, attachments=ATTACHMENTS)

    assert [payload["execution_action"] for payload in callbacks] == ["complete"]


def test_other_authenticated_account_is_a_warning() -> None:
    helper = _helper(AWS_ACCESS_KEY)

    auth, warning, terminal = _process(
        helper, AWS_FORM, attachments=ATTACHMENTS, stdout=_aws_box(OTHER_ACCOUNT)
    )

    assert auth["execution_status"] == "INFO"
    assert warning["execution_status"] == "WARNING"
    assert warning["execution_action"] == "prerequisite_check"
    assert OTHER_ACCOUNT in warning["execution_message"]
    assert ACCOUNT in warning["execution_message"]
    assert terminal["execution_status"] == "SUCCESS"
    warnings = [call.args[0] for call in helper.injector_logger.warning.mock_calls]
    assert "[PROWLER_INJECTOR] - Authenticated AWS account mismatch" in warnings


def test_assume_role_of_another_account_is_rejected_before_the_scan() -> None:
    (terminal,) = _process(
        _helper(_assume_role(OTHER_ACCOUNT)), AWS_FORM, attachments=ATTACHMENTS
    )

    assert terminal["execution_status"] == "ERROR"
    assert _Contract.executed == []
    assert "CREDENTIAL_ACCOUNT_MISMATCH" in terminal["execution_message"]
    assert OTHER_ACCOUNT in terminal["execution_message"]
    assert ACCOUNT in terminal["execution_message"]


def test_assume_role_of_the_inject_account_runs() -> None:
    callbacks = _process(
        _helper(_assume_role(ACCOUNT)), AWS_FORM, attachments=ATTACHMENTS
    )

    assert callbacks[-1]["execution_status"] == "SUCCESS"
    assert len(_Contract.executed) == 1


def test_region_comes_from_the_credential() -> None:
    callbacks = _process(_helper(AWS_ACCESS_KEY), AWS_FORM, attachments=ATTACHMENTS)

    assert callbacks[-1]["execution_status"] == "SUCCESS"
    (executed,) = _Contract.executed
    assert executed.scope_value("aws_default_region") == "us-east-1"


def test_missing_subscription_is_reported_on_the_credential() -> None:
    managed_identity = {
        "type": "AZURE_MANAGED_IDENTITY",
        "value": {"azure_environment": "AzureCloud"},
    }

    (terminal,) = _process(
        _helper(managed_identity),
        {},
        attachments=ATTACHMENTS,
        contract=_AzureContract,
    )

    assert terminal["execution_status"] == "ERROR"
    assert _Contract.executed == []
    message = terminal["execution_message"]
    assert "CREDENTIAL_SCOPE_MISSING" in message
    assert f"The credential {REFERENCE} has no Azure subscription ID." in message
    assert "Set it on the credential, then run it again." in message


def test_platform_unavailable_has_its_own_code() -> None:
    helper = Mock()
    helper.api.inject.resolve_attachment_secret.side_effect = CredentialResolutionError(
        CredentialErrorCode.CREDENTIAL_RESOLUTION_UNAVAILABLE, REFERENCE
    )

    (terminal,) = _process(helper, AWS_FORM, attachments=ATTACHMENTS)

    assert terminal["execution_status"] == "ERROR"
    assert "CREDENTIAL_RESOLUTION_UNAVAILABLE" in terminal["execution_message"]
    assert "could not be resolved" in terminal["execution_message"]
