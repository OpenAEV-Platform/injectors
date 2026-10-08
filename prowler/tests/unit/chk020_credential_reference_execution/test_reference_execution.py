"""Resolution and materialization of a referenced credential for Prowler."""

# Fake secret values are compared on purpose, hence S105.
# ruff: noqa: D101, D102, D103, S105

from __future__ import annotations

import base64
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar
from unittest.mock import Mock

import pytest
from pydantic import SecretStr
from pyoaev.credential import (  # type: ignore[import-untyped]
    CredentialAttachment,
    CredentialErrorCode,
    CredentialResolutionError,
    parse_resolved_secret,
)

from prowler._core.cli_engine import (
    CommandResult,
    ExecutionSpecification,
    OutputSpecification,
)
from prowler._core.prowler_client import (
    ProwlerClientFactory,
    TemporaryCredentialLeaseFactory,
    TemporaryOutputWorkspaceFactory,
)
from prowler._core.prowler_client.provider_adapter import ProviderInvocationAdapter
from prowler.contracts import (
    BaseProwlerContract,
    ContractExecutionOutcome,
    ProwlerContracts,
    stable_contract_id,
)
from prowler.models.configs.config_loader import ProwlerConfig
from prowler.models.provider_inputs import (
    AwsReferenceProviderInput,
    AzureReferenceProviderInput,
    CredentialReferenceProviderInput,
    GcpReferenceProviderInput,
)

REFERENCE = "3f1c1e5e-0000-4000-8000-000000000001"
AUTHORISATION_CODE = "AUTHORISATION-CODE-CANARY"
ATTACHMENT = CredentialAttachment(REFERENCE, AUTHORISATION_CODE)
GCP_SERVICE_ACCOUNT_JSON = b'{"type": "service_account", "private_key": "KEY-CANARY"}'

# One resolution payload per cloud secret type; every secret value ends with
# CANARY so that leaks can be detected in any textual output.
PAYLOADS: dict[str, dict[str, Any]] = {
    "AWS_ACCESS_KEY": {
        "type": "AWS_ACCESS_KEY",
        "value": {
            "aws_default_region": "us-east-1",
            "aws_access_key_id": "ACCESS-KEY-CANARY",
            "aws_secret_access_key": "SECRET-KEY-CANARY",
            "aws_session_token": "SESSION-TOKEN-CANARY",
        },
    },
    "AWS_ASSUME_ROLE": {
        "type": "AWS_ASSUME_ROLE",
        "value": {
            "aws_default_region": "us-east-2",
            "aws_role_arn": "arn:aws:iam::123456789012:role/audit",
            "aws_source_identity_type": "STATIC_ACCESS_KEY",
            "aws_external_id": "EXTERNAL-ID-CANARY",
            "aws_source_profile_access_key_id": "SOURCE-KEY-CANARY",
            "aws_source_profile_secret_access_key": "SOURCE-SECRET-CANARY",
        },
    },
    "AZURE_SERVICE_PRINCIPAL": {
        "type": "AZURE_SERVICE_PRINCIPAL",
        "value": {
            "azure_environment": "AzureChinaCloud",
            "azure_client_id": "client-id",
            "azure_client_secret": "CLIENT-SECRET-CANARY",
            "azure_tenant_id": "tenant-id",
            "azure_subscription_id": "secret-subscription",
        },
    },
    "AZURE_MANAGED_IDENTITY": {
        "type": "AZURE_MANAGED_IDENTITY",
        "value": {"azure_environment": "AzureUSGovernment", "azure_client_id": "mi"},
    },
    "GCP_SERVICE_ACCOUNT": {
        "type": "GCP_SERVICE_ACCOUNT",
        "value": {
            "gcp_scope": "googleapis.com",
            "gcp_project_id": "secret-project",
            "gcp_private_key_json": base64.b64encode(GCP_SERVICE_ACCOUNT_JSON).decode(),
        },
    },
    "GCP_OAUTH2": {
        "type": "GCP_OAUTH2",
        "value": {
            "gcp_scope": "googleapis.com",
            "gcp_oauth_client_id": "oauth-client",
            "gcp_oauth_client_secret": "OAUTH-SECRET-CANARY",
            "gcp_oauth_refresh_token": "REFRESH-TOKEN-CANARY",
        },
    },
}

AWS_INPUT = {"aws_account_id": "123456789012", "aws_region": "eu-west-1"}
AZURE_INPUT = {"azure_subscription_id": "form-subscription", "azure_provider": "Azure"}
GCP_INPUT = {"gcp_project_id": "form-project"}


PROVIDER_NAMES: dict[type[Any], str] = {
    AwsReferenceProviderInput: "aws",
    AzureReferenceProviderInput: "azure",
    GcpReferenceProviderInput: "gcp",
}


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


def _resolved(secret_type: str) -> Any:
    return parse_resolved_secret(PAYLOADS[secret_type], reference=REFERENCE)


def _reference_input(model: type[Any], form: dict[str, str], secret_type: str) -> Any:
    provider = model(
        provider=PROVIDER_NAMES[model], credential_attachment=ATTACHMENT, **form
    )
    return provider.with_resolved_secret(_resolved(secret_type))


def _adapter(tmp_path: Path) -> ProviderInvocationAdapter:
    return ProviderInvocationAdapter(
        TemporaryCredentialLeaseFactory(temporary_root=tmp_path)
    )


def _environment(invocation: Any) -> dict[str, str]:
    """Reveal the invocation environment, asserting every value is wrapped."""
    revealed: dict[str, str] = {}
    for name, value in invocation.environment:
        if name == "AWS_ENDPOINT_URL":
            revealed[name] = value
            continue
        assert isinstance(value, SecretStr), name
        revealed[name] = value.get_secret_value()
    return revealed


def _leftovers(tmp_path: Path) -> list[Path]:
    return list(tmp_path.iterdir())


@pytest.mark.parametrize(
    ("form", "expected_region"),
    (
        ({}, "us-east-1"),
        ({"aws_default_region": None}, "eu-west-1"),
    ),
)
def test_aws_access_key_uses_the_secret_region_then_the_form_region(
    tmp_path: Path, form: dict[str, Any], expected_region: str
) -> None:
    payload = json.loads(json.dumps(PAYLOADS["AWS_ACCESS_KEY"]))
    payload["value"].update(form)
    provider = AwsReferenceProviderInput(
        provider="aws", credential_attachment=ATTACHMENT, **AWS_INPUT
    ).with_resolved_secret(parse_resolved_secret(payload))

    invocation = _adapter(tmp_path).adapt(provider)

    assert invocation.arguments == ("aws", "--region", expected_region)
    environment = _environment(invocation)
    assert environment["AWS_ACCESS_KEY_ID"] == "ACCESS-KEY-CANARY"
    assert environment["AWS_SECRET_ACCESS_KEY"] == "SECRET-KEY-CANARY"
    assert environment["AWS_SESSION_TOKEN"] == "SESSION-TOKEN-CANARY"
    assert _leftovers(tmp_path) == []


def test_aws_reference_keeps_the_form_endpoint_override(tmp_path: Path) -> None:
    provider = _reference_input(
        AwsReferenceProviderInput,
        {**AWS_INPUT, "aws_endpoint_url": "https://aws.example.test"},
        "AWS_ACCESS_KEY",
    )

    invocation = _adapter(tmp_path).adapt(provider)

    assert _environment(invocation)["AWS_ENDPOINT_URL"] == "https://aws.example.test"


def test_aws_assume_role_selects_a_private_profile(tmp_path: Path) -> None:
    provider = _reference_input(AwsReferenceProviderInput, AWS_INPUT, "AWS_ASSUME_ROLE")

    invocation = _adapter(tmp_path).adapt(provider)

    assert invocation.arguments == ("aws", "--region", "us-east-2")
    environment = _environment(invocation)
    assert set(environment) == {
        "AWS_PROFILE",
        "AWS_CONFIG_FILE",
        "AWS_SHARED_CREDENTIALS_FILE",
    }
    config = Path(environment["AWS_CONFIG_FILE"]).read_text(encoding="utf-8")
    assert "role_arn = arn:aws:iam::123456789012:role/audit" in config
    credentials = Path(environment["AWS_SHARED_CREDENTIALS_FILE"])
    assert "SOURCE-SECRET-CANARY" in credentials.read_text(encoding="utf-8")
    assert credentials.parent.parent == tmp_path

    for lease in invocation.credential_leases:
        lease.cleanup()
    assert _leftovers(tmp_path) == []


@pytest.mark.parametrize(
    ("secret_type", "authentication", "subscription", "region"),
    (
        (
            "AZURE_SERVICE_PRINCIPAL",
            "--sp-env-auth",
            "secret-subscription",
            "AzureChinaCloud",
        ),
        (
            "AZURE_MANAGED_IDENTITY",
            "--managed-identity-auth",
            "form-subscription",
            "AzureUSGovernment",
        ),
    ),
)
def test_azure_flags_follow_the_secret_type(
    tmp_path: Path,
    secret_type: str,
    authentication: str,
    subscription: str,
    region: str,
) -> None:
    provider = _reference_input(AzureReferenceProviderInput, AZURE_INPUT, secret_type)

    invocation = _adapter(tmp_path).adapt(provider)

    assert invocation.arguments == (
        "azure",
        authentication,
        "--subscription-id",
        subscription,
        "--azure-region",
        region,
    )
    environment = _environment(invocation)
    assert environment["AZURE_AUTHORITY_HOST"].startswith("https://login.")
    if secret_type == "AZURE_SERVICE_PRINCIPAL":
        assert environment["AZURE_CLIENT_SECRET"] == "CLIENT-SECRET-CANARY"
        assert environment["AZURE_TENANT_ID"] == "tenant-id"
    else:
        assert "AZURE_CLIENT_SECRET" not in environment
        assert environment["AZURE_CLIENT_ID"] == "mi"


@pytest.mark.parametrize(
    ("secret_type", "project"),
    (("GCP_SERVICE_ACCOUNT", "secret-project"), ("GCP_OAUTH2", "form-project")),
)
def test_gcp_uses_the_materialized_credentials_file(
    tmp_path: Path, secret_type: str, project: str
) -> None:
    provider = _reference_input(GcpReferenceProviderInput, GCP_INPUT, secret_type)

    invocation = _adapter(tmp_path).adapt(provider)

    credentials_file = Path(invocation.arguments[2])
    assert invocation.arguments == (
        "gcp",
        "--credentials-file",
        str(credentials_file),
        "--project-id",
        project,
    )
    assert _environment(invocation)["GOOGLE_APPLICATION_CREDENTIALS"] == str(
        credentials_file
    )
    content = credentials_file.read_bytes()
    if secret_type == "GCP_SERVICE_ACCOUNT":
        assert content == GCP_SERVICE_ACCOUNT_JSON
    else:
        assert json.loads(content)["type"] == "authorized_user"

    for lease in invocation.credential_leases:
        lease.cleanup()
    assert not credentials_file.exists()
    assert _leftovers(tmp_path) == []


@pytest.mark.parametrize("secret_type", tuple(PAYLOADS))
def test_invocation_rendering_never_contains_a_secret_value(
    tmp_path: Path, secret_type: str
) -> None:
    model, form = {
        "AWS": (AwsReferenceProviderInput, AWS_INPUT),
        "AZURE": (AzureReferenceProviderInput, AZURE_INPUT),
        "GCP": (GcpReferenceProviderInput, GCP_INPUT),
    }[secret_type.split("_")[0]]
    provider = _reference_input(model, form, secret_type)

    invocation = _adapter(tmp_path).adapt(provider)

    for rendering in (
        repr(invocation),
        repr(provider),
        json.dumps(provider.model_dump(mode="json")),
        json.dumps(provider.safe_log_metadata()),
    ):
        assert "CANARY" not in rendering
    assert provider.safe_log_metadata()["credential_secret_type"] == secret_type
    for lease in invocation.credential_leases:
        lease.cleanup()


def test_unresolved_reference_is_rejected_before_materialization(
    tmp_path: Path,
) -> None:
    provider = AwsReferenceProviderInput(
        provider="aws", credential_attachment=ATTACHMENT, **AWS_INPUT
    )

    with pytest.raises(ValueError, match="must be resolved"):
        _adapter(tmp_path).adapt(provider)
    assert _leftovers(tmp_path) == []


def test_mismatched_secret_is_incompatible_and_leaves_no_file(tmp_path: Path) -> None:
    provider = _reference_input(
        AwsReferenceProviderInput, AWS_INPUT, "GCP_SERVICE_ACCOUNT"
    )

    with pytest.raises(CredentialResolutionError) as raised:
        _adapter(tmp_path).adapt(provider)
    assert raised.value.code is CredentialErrorCode.CREDENTIAL_INCOMPATIBLE
    assert _leftovers(tmp_path) == []


@dataclass
class _Engine:
    failure: BaseException | None = None
    requests: list[Any] = field(default_factory=list)
    credential_files: list[Path] = field(default_factory=list)

    def create(self) -> _Engine:
        return self

    def run(self, request: Any) -> CommandResult:
        self.requests.append(request)
        environment = dict(request.environment)
        credentials = environment["GOOGLE_APPLICATION_CREDENTIALS"]
        self.credential_files.append(Path(credentials.get_secret_value()))
        assert self.credential_files[-1].exists()
        if self.failure is not None:
            raise self.failure
        directory = Path(
            request.arguments[request.arguments.index("--output-directory") + 1]
        )
        (directory / "findings.ocsf.json").write_bytes(b"[]")
        return CommandResult(specification=_specification(), return_code=0)


def _client_factory(engine: _Engine, tmp_path: Path) -> ProwlerClientFactory:
    credentials_root = tmp_path / "credentials"
    credentials_root.mkdir()
    output_root = tmp_path / "outputs"
    output_root.mkdir()
    return ProwlerClientFactory(
        engine_factory=engine,
        credential_lease_factory=TemporaryCredentialLeaseFactory(
            temporary_root=credentials_root
        ),
        output_workspace_factory=TemporaryOutputWorkspaceFactory(
            platform_name="nt", temporary_root=output_root
        ),
    )


@pytest.mark.parametrize("failure", (None, RuntimeError("engine failure")))
def test_client_removes_materialized_files_on_success_and_failure(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    failure: BaseException | None,
) -> None:
    caplog.set_level(logging.DEBUG)
    engine = _Engine(failure=failure)
    provider = _reference_input(
        GcpReferenceProviderInput, GCP_INPUT, "GCP_SERVICE_ACCOUNT"
    )
    config = ProwlerConfig(executable_path=str(tmp_path / "prowler"))

    if failure is None:
        _client_factory(engine, tmp_path).run(config, provider)
    else:
        with pytest.raises(RuntimeError, match="engine failure"):
            _client_factory(engine, tmp_path).run(config, provider)

    assert engine.credential_files
    assert not engine.credential_files[0].exists()
    assert list((tmp_path / "credentials").iterdir()) == []
    metadata = next(
        record.__dict__["prowler_metadata"]
        for record in caplog.records
        if record.getMessage() == "Prowler referenced credential metadata"
    )
    assert metadata == {
        "credential_reference_present": True,
        "credential_reference": REFERENCE,
        "credential_secret_type": "GCP_SERVICE_ACCOUNT",
    }
    rendered = "\n".join(str(record.__dict__) for record in caplog.records)
    assert "CANARY" not in rendered


class _RecordingContract(BaseProwlerContract):
    """Record the provider input handed to the execution."""

    contract_id: ClassVar[str] = str(stable_contract_id("aws"))
    external_id = "prowler:aws"
    route_name = "aws"
    provider = "aws"
    family = "base"
    label = "Reference execution test"
    executed: ClassVar[list[Any]] = []

    def execute(self, config: Any, provider: Any) -> ContractExecutionOutcome:
        del config
        self.executed.append(provider)
        return ContractExecutionOutcome(
            command_result=CommandResult(specification=_specification(), return_code=0)
        )


class _RecordingKubernetesContract(_RecordingContract):
    contract_id: ClassVar[str] = str(stable_contract_id("kubernetes"))
    external_id = "prowler:kubernetes"
    route_name = "kubernetes"
    provider = "kubernetes"


def _process(
    helper: Mock,
    content: dict[str, str],
    *,
    attachments: object,
    contract: type[_RecordingContract] = _RecordingContract,
) -> dict[str, Any]:
    """Process one job and return the terminal callback payload."""
    from prowler.injector import ProwlerInjector

    _RecordingContract.executed = []
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
    data: dict[str, Any] = helper.api.inject.execution_callback.call_args.kwargs["data"]
    return data


_ATTACHMENTS = {
    "credential_references": [REFERENCE],
    "authorisation_code": AUTHORISATION_CODE,
}
_LEGACY_AWS = {
    **AWS_INPUT,
    "aws_access_key_id": "LEGACY-KEY-CANARY",
    "aws_secret_access_key": "LEGACY-SECRET-CANARY",
}


def test_injector_resolves_between_reception_and_callback() -> None:
    helper = Mock()
    helper.api.inject.resolve_attachment_secret.return_value = PAYLOADS[
        "AWS_ACCESS_KEY"
    ]

    callback = _process(helper, _LEGACY_AWS, attachments=_ATTACHMENTS)

    assert callback["execution_status"] == "SUCCESS"
    helper.api.inject.resolve_attachment_secret.assert_called_once_with(
        "inject-test", REFERENCE, AUTHORISATION_CODE
    )
    calls = [name for name, _args, _kwargs in helper.api.inject.mock_calls]
    assert calls.index("execution_reception") < calls.index("resolve_attachment_secret")
    assert calls.index("resolve_attachment_secret") < calls.index("execution_callback")
    (executed,) = _RecordingContract.executed
    assert isinstance(executed, AwsReferenceProviderInput)
    assert executed.resolved_secret == _resolved("AWS_ACCESS_KEY")
    assert not hasattr(executed, "aws_access_key_id")
    logged = str(helper.injector_logger.mock_calls)
    assert "CANARY" not in logged
    assert "AWS_ACCESS_KEY" in logged


def test_injector_without_reference_sends_no_resolution_request() -> None:
    helper = Mock()

    callback = _process(helper, _LEGACY_AWS, attachments=None)

    assert callback["execution_status"] == "SUCCESS"
    helper.api.inject.resolve_attachment_secret.assert_not_called()
    (executed,) = _RecordingContract.executed
    assert not isinstance(executed, CredentialReferenceProviderInput)


@pytest.mark.parametrize(
    "code",
    (
        CredentialErrorCode.CREDENTIAL_NOT_FOUND,
        CredentialErrorCode.CREDENTIAL_INACTIVE,
        CredentialErrorCode.CREDENTIAL_ACCESS_DENIED,
    ),
)
def test_injector_resolution_failure_ends_in_error_without_execution(
    code: CredentialErrorCode,
) -> None:
    helper = Mock()
    helper.api.inject.resolve_attachment_secret.side_effect = CredentialResolutionError(
        code, REFERENCE
    )

    callback = _process(helper, AWS_INPUT, attachments=_ATTACHMENTS)

    assert callback["execution_status"] == "ERROR"
    assert _RecordingContract.executed == []


def test_injector_incompatible_secret_ends_in_error_without_execution() -> None:
    helper = Mock()
    helper.api.inject.resolve_attachment_secret.return_value = PAYLOADS[
        "AZURE_SERVICE_PRINCIPAL"
    ]

    callback = _process(helper, AWS_INPUT, attachments=_ATTACHMENTS)

    assert callback["execution_status"] == "ERROR"
    assert _RecordingContract.executed == []
    assert "CANARY" not in json.dumps(callback, default=str)


def test_kubernetes_reference_is_incompatible_without_resolution() -> None:
    helper = Mock()

    callback = _process(
        helper,
        {"kubernetes_context": "context", "kubernetes_kubeconfig": "KUBE-CANARY"},
        attachments=_ATTACHMENTS,
        contract=_RecordingKubernetesContract,
    )

    assert callback["execution_status"] == "ERROR"
    helper.api.inject.resolve_attachment_secret.assert_not_called()
    assert _RecordingContract.executed == []
