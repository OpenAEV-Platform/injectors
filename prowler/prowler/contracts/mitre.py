"""Executable MITRE ATT&CK compliance contracts for cloud providers."""

from prowler._core.prowler_client import ComplianceSelector

from .base import ProviderName
from .compliance import FixedComplianceContract

_MITRE_BY_PROVIDER: dict[ProviderName, ComplianceSelector] = {
    "aws": "mitre_attack_aws",
    "azure": "mitre_attack_azure",
    "gcp": "mitre_attack_gcp",
}


class MitreComplianceContract(FixedComplianceContract):
    """Execute one provider-owned MITRE selector through the CHK.004 seam."""

    compliance_by_provider = _MITRE_BY_PROVIDER
    framework_name = "MITRE"


class AwsMitreContract(MitreComplianceContract):
    """Run the Prowler 5.36 AWS MITRE ATT&CK framework."""

    contract_id = "5fe66d58-ad58-5e06-aa0a-0243e79607ae"
    external_id = "prowler:mitre/aws"
    route_name = "mitre/aws"
    provider = "aws"
    label = "Prowler AWS MITRE ATT&CK"
    compliance_selector = "mitre_attack_aws"


class AzureMitreContract(MitreComplianceContract):
    """Run the Prowler 5.36 Azure MITRE ATT&CK framework."""

    contract_id = "022ab8d9-ae87-593d-ac9d-84650e225c35"
    external_id = "prowler:mitre/azure"
    route_name = "mitre/azure"
    provider = "azure"
    label = "Prowler Azure MITRE ATT&CK"
    compliance_selector = "mitre_attack_azure"


class GcpMitreContract(MitreComplianceContract):
    """Run the Prowler 5.36 GCP MITRE ATT&CK framework."""

    contract_id = "52eb8624-9bb2-522d-8772-d9c738f8853b"
    external_id = "prowler:mitre/gcp"
    route_name = "mitre/gcp"
    provider = "gcp"
    label = "Prowler GCP MITRE ATT&CK"
    compliance_selector = "mitre_attack_gcp"
