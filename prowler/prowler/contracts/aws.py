"""Executable complete-scope and service-specific AWS contracts."""

from collections.abc import Sequence
from dataclasses import replace
from typing import ClassVar

from prowler._core.prowler_client import AwsServiceSelector
from prowler.models.configs.config_loader import ProwlerConfig
from prowler.models.findings import (
    OcsfDecodeError,
    OcsfMappingError,
    OpenAevFinding,
    map_command_result_with_evidence,
)
from prowler.models.provider_inputs import AwsProviderInput, ProviderInput

from .base import BaseProwlerContract, ContractExecutionOutcome, RouteFamily


class AwsBaseContract(BaseProwlerContract):
    """Run the complete AWS provider scope and retain only mapped AWS findings."""

    contract_id: ClassVar[str] = "a0464aa7-9451-54ea-bc00-3e89019a315a"
    external_id: ClassVar[str] = "prowler:aws"
    route_name: ClassVar[str] = "aws"
    provider = "aws"
    family: ClassVar[RouteFamily] = "base"
    label = "Prowler AWS"
    check_filters = ()

    @staticmethod
    def _aws_findings(
        findings: Sequence[OpenAevFinding],
    ) -> tuple[OpenAevFinding, ...]:
        """Retain ordered AWS findings with one canonical provider spelling."""
        return tuple(
            finding.model_copy(update={"cloud_provider": "aws"})
            for finding in findings
            if finding.cloud_provider.casefold() == "aws"
        )

    def execute(
        self, config: ProwlerConfig, provider: ProviderInput
    ) -> ContractExecutionOutcome:
        """Map one complete-scope result, preserving ordered AWS findings only."""
        outcome = super().execute(config, provider)
        if outcome.error is not None or outcome.command_result.return_code != 0:
            return outcome
        return replace(outcome, findings=self._aws_findings(outcome.findings))


class AwsServiceContract(AwsBaseContract):
    """Execute one route-owned AWS service selector through the CHK.004 seam."""

    family = "service"
    service_selector: ClassVar[AwsServiceSelector]

    def safe_request_info(self, provider: ProviderInput | None) -> dict[str, object]:
        """Identify the service through safe route metadata, never form input."""
        info = super().safe_request_info(provider)
        info["filters"] = f"service={self.service_selector}"
        return info

    def execute(
        self, config: ProwlerConfig, provider: ProviderInput
    ) -> ContractExecutionOutcome:
        """Reject invalid route combinations before one service-specific client call."""
        if self.service_selector not in ("iam", "s3", "ec2"):
            raise ValueError("unsupported AWS service selector")
        if not isinstance(provider, AwsProviderInput):
            raise ValueError("AWS service selector requires an AWS provider")
        result = self._client_factory.run(
            config,
            provider,
            check_filters=self.check_filters,
            service_selector=self.service_selector,
        )
        if result.error is not None or result.return_code != 0:
            return ContractExecutionOutcome(command_result=result, error=result.error)
        try:
            mapping = map_command_result_with_evidence(result)
        except (OcsfDecodeError, OcsfMappingError) as error:
            return ContractExecutionOutcome(command_result=result, error=error)
        outcome = ContractExecutionOutcome(
            command_result=result,
            findings=mapping.findings,
            raw_record_count=mapping.raw_record_count,
            raw_output_bytes=mapping.raw_output_bytes,
            raw_preview=mapping.raw_preview,
        )
        return replace(outcome, findings=self._aws_findings(outcome.findings))


class AwsIamContract(AwsServiceContract):
    """Run only Prowler AWS IAM checks."""

    contract_id = "056a2645-d7a4-5043-a54b-5f1df35f5aa0"
    external_id = "prowler:aws/iam"
    route_name = "aws/iam"
    label = "Prowler AWS IAM"
    service_selector = "iam"


class AwsS3Contract(AwsServiceContract):
    """Run only Prowler AWS S3 checks."""

    contract_id = "f6b85401-358f-5d31-96ad-c64a44466228"
    external_id = "prowler:aws/s3"
    route_name = "aws/s3"
    label = "Prowler AWS S3"
    service_selector = "s3"


class AwsEc2Contract(AwsServiceContract):
    """Run only Prowler AWS EC2 checks."""

    contract_id = "302268dc-8792-5383-b32a-d2fe2e74b2e9"
    external_id = "prowler:aws/ec2"
    route_name = "aws/ec2"
    label = "Prowler AWS EC2"
    service_selector = "ec2"
