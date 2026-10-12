"""Executable CIS compliance contracts for the four supported providers."""

from prowler._core.prowler_client import ComplianceSelector

from .base import ProviderName
from .compliance import FixedComplianceContract

_CIS_BY_PROVIDER: dict[ProviderName, ComplianceSelector] = {
    "aws": "cis_3.0_aws",
    "azure": "cis_3.0_azure",
    "gcp": "cis_3.0_gcp",
    "kubernetes": "cis_1.12_kubernetes",
}


class CisComplianceContract(FixedComplianceContract):
    """Execute one provider-owned CIS selector through the CHK.004 seam."""

    compliance_by_provider = _CIS_BY_PROVIDER
    framework_name = "CIS"


class AwsCisContract(CisComplianceContract):
    """Run the Prowler 5.36 AWS CIS 3.0 framework."""

    contract_id = "f0766dbc-b04f-5b4b-b762-0aee15884ead"
    external_id = "prowler:cis/aws"
    route_name = "cis/aws"
    provider = "aws"
    label = "Prowler AWS CIS"
    compliance_selector = "cis_3.0_aws"


class AzureCisContract(CisComplianceContract):
    """Run the Prowler 5.36 Azure CIS 3.0 framework."""

    contract_id = "3acf796f-71a9-523a-b6dc-fca321ad3bac"
    external_id = "prowler:cis/azure"
    route_name = "cis/azure"
    provider = "azure"
    label = "Prowler Azure CIS"
    compliance_selector = "cis_3.0_azure"


class GcpCisContract(CisComplianceContract):
    """Run the Prowler 5.36 GCP CIS 3.0 framework."""

    contract_id = "aec2729b-60c5-59e9-9383-78c5b34507cb"
    external_id = "prowler:cis/gcp"
    route_name = "cis/gcp"
    provider = "gcp"
    label = "Prowler GCP CIS"
    compliance_selector = "cis_3.0_gcp"


class KubernetesCisContract(CisComplianceContract):
    """Run the Prowler 5.36 Kubernetes CIS 1.12 framework."""

    contract_id = "a846a50c-16b3-5df5-87cf-de279637a2e9"
    external_id = "prowler:cis/kubernetes"
    route_name = "cis/kubernetes"
    provider = "kubernetes"
    label = "Prowler Kubernetes CIS"
    compliance_selector = "cis_1.12_kubernetes"
