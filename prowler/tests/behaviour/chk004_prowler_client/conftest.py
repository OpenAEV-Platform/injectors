"""Fixtures local to CHK.004 behaviour tests."""

# ruff: noqa: D102, D103

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr

from prowler._core.cli_engine import CommandResult, ExecutionSpecification
from prowler.models.provider_inputs import (
    AwsProviderInput,
    AzureProviderInput,
    GcpProviderInput,
    KubernetesProviderInput,
)


@dataclass
class RecordingEngine:
    requests: list[Any] = field(default_factory=list)
    result: Any = None
    raised: BaseException | None = None
    inspect_paths: tuple[Path, ...] = ()
    observed_modes: list[int] = field(default_factory=list)
    observed_contents: list[str] = field(default_factory=list)

    def run(self, request: Any) -> Any:
        self.requests.append(request)
        paths = list(self.inspect_paths)
        for flag in ("--credentials-file", "--kubeconfig-file"):
            if flag in request.arguments:
                paths.append(Path(request.arguments[request.arguments.index(flag) + 1]))
        for path in paths:
            self.observed_modes.append(path.stat().st_mode & 0o777)
            self.observed_contents.append(path.read_text(encoding="utf-8"))
        if self.raised is not None:
            raise self.raised
        if self.result is None:
            specification = ExecutionSpecification.from_request(request)
            self.result = CommandResult(
                specification=specification,
                stdout=b'{"raw":"ocsf"}\n',
                return_code=0,
                parsed=b'{"raw":"ocsf"}\n',
            )
        return self.result


@dataclass
class RecordingEngineFactory:
    engine: RecordingEngine
    create_calls: int = 0

    def create(self) -> RecordingEngine:
        self.create_calls += 1
        return self.engine


@pytest.fixture
def recording_engine() -> RecordingEngine:
    return RecordingEngine()


@pytest.fixture
def provider_inputs() -> dict[str, Any]:
    return {
        "AWS": AwsProviderInput(
            provider="aws",
            aws_access_key_id="AKIA_TEST",
            aws_secret_access_key=SecretStr("aws-secret"),
            aws_session_token=SecretStr("aws-session"),
            aws_account_id="123456789012",
            aws_region="eu-west-1",
        ),
        "Azure": AzureProviderInput(
            provider="azure",
            azure_tenant_id="tenant-id",
            azure_client_id="client-id",
            azure_client_secret=SecretStr("azure-secret"),
            azure_subscription_id="subscription-id",
            azure_provider="AzureUSGovernment",
        ),
        "GCP": GcpProviderInput(
            provider="gcp",
            gcp_service_account_json=SecretStr('{"private_key":"gcp-secret"}'),
            gcp_project_id="project-id",
        ),
        "Kubernetes": KubernetesProviderInput(
            provider="kubernetes",
            kubernetes_kubeconfig=SecretStr("kube-secret"),
            kubernetes_context="cluster-context",
        ),
    }
