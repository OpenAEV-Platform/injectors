"""Executable NIS2 and ISO 27001 compliance contracts."""

from prowler._core.prowler_client import ComplianceSelector

from .base import ProviderName
from .compliance import FixedComplianceContract

_NIS2_BY_PROVIDER: dict[ProviderName, ComplianceSelector] = {
    "aws": "nis2_aws",
    "azure": "nis2_azure",
    "gcp": "nis2_gcp",
}
_ISO27001_BY_PROVIDER: dict[ProviderName, ComplianceSelector] = {
    "aws": "iso27001_2022_aws",
    "azure": "iso27001_2022_azure",
    "gcp": "iso27001_2022_gcp",
    "kubernetes": "iso27001_2022_kubernetes",
}


class Nis2ComplianceContract(FixedComplianceContract):
    """Execute one provider-owned NIS2 selector through the CHK.004 seam."""

    compliance_by_provider = _NIS2_BY_PROVIDER
    framework_name = "NIS2"


class Iso27001ComplianceContract(FixedComplianceContract):
    """Execute one provider-owned ISO 27001 selector through the CHK.004 seam."""

    compliance_by_provider = _ISO27001_BY_PROVIDER
    framework_name = "ISO27001"


class AwsNis2Contract(Nis2ComplianceContract):
    """Run the Prowler 5.36 AWS NIS2 framework."""

    contract_id = "eff788bc-44ef-5381-840a-e56ecc34db99"
    external_id = "prowler:nis2/aws"
    route_name = "nis2/aws"
    provider = "aws"
    label = "Prowler AWS NIS2"
    compliance_selector = "nis2_aws"


class AzureNis2Contract(Nis2ComplianceContract):
    """Run the Prowler 5.36 Azure NIS2 framework."""

    contract_id = "7799ecf6-98db-5045-8154-65c085c6ded7"
    external_id = "prowler:nis2/azure"
    route_name = "nis2/azure"
    provider = "azure"
    label = "Prowler Azure NIS2"
    compliance_selector = "nis2_azure"


class GcpNis2Contract(Nis2ComplianceContract):
    """Run the Prowler 5.36 GCP NIS2 framework."""

    contract_id = "12139fd2-48d5-51ba-ba60-9bd072a8720b"
    external_id = "prowler:nis2/gcp"
    route_name = "nis2/gcp"
    provider = "gcp"
    label = "Prowler GCP NIS2"
    compliance_selector = "nis2_gcp"


class AwsIso27001Contract(Iso27001ComplianceContract):
    """Run the Prowler 5.36 AWS ISO 27001:2022 framework."""

    contract_id = "3adfd3d1-8a80-5bb8-b9f8-d28d1d54a2a5"
    external_id = "prowler:iso27001/aws"
    route_name = "iso27001/aws"
    provider = "aws"
    label = "Prowler AWS ISO27001"
    compliance_selector = "iso27001_2022_aws"


class AzureIso27001Contract(Iso27001ComplianceContract):
    """Run the Prowler 5.36 Azure ISO 27001:2022 framework."""

    contract_id = "51f5a42a-fed2-50d7-a438-4c9d38139fce"
    external_id = "prowler:iso27001/azure"
    route_name = "iso27001/azure"
    provider = "azure"
    label = "Prowler Azure ISO27001"
    compliance_selector = "iso27001_2022_azure"


class GcpIso27001Contract(Iso27001ComplianceContract):
    """Run the Prowler 5.36 GCP ISO 27001:2022 framework."""

    contract_id = "0de81cd3-21fc-5225-ba37-7ccc708bd633"
    external_id = "prowler:iso27001/gcp"
    route_name = "iso27001/gcp"
    provider = "gcp"
    label = "Prowler GCP ISO27001"
    compliance_selector = "iso27001_2022_gcp"


class KubernetesIso27001Contract(Iso27001ComplianceContract):
    """Run the Prowler 5.36 Kubernetes ISO 27001:2022 framework."""

    contract_id = "a52206f3-c3da-5120-9f1f-965ec9efdcc6"
    external_id = "prowler:iso27001/kubernetes"
    route_name = "iso27001/kubernetes"
    provider = "kubernetes"
    label = "Prowler Kubernetes ISO27001"
    compliance_selector = "iso27001_2022_kubernetes"
