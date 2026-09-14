"""Immutable canonical CHK.006 route descriptors."""

from dataclasses import dataclass

from .base import ProviderName, RouteFamily


@dataclass(frozen=True)
class RouteDescriptor:
    """A route name and its provider/family metadata, never a platform UUID."""

    route_name: str
    provider: ProviderName
    family: RouteFamily


ROUTE_CATALOG: tuple[RouteDescriptor, ...] = (
    RouteDescriptor("aws", "aws", "base"),
    RouteDescriptor("azure", "azure", "base"),
    RouteDescriptor("gcp", "gcp", "base"),
    RouteDescriptor("kubernetes", "kubernetes", "base"),
    RouteDescriptor("aws/iam", "aws", "service"),
    RouteDescriptor("aws/s3", "aws", "service"),
    RouteDescriptor("aws/ec2", "aws", "service"),
    RouteDescriptor("azure/iam", "azure", "service"),
    RouteDescriptor("azure/storage", "azure", "service"),
    RouteDescriptor("gcp/iam", "gcp", "service"),
    RouteDescriptor("gcp/compute", "gcp", "service"),
    RouteDescriptor("cis/aws", "aws", "compliance"),
    RouteDescriptor("cis/azure", "azure", "compliance"),
    RouteDescriptor("cis/gcp", "gcp", "compliance"),
    RouteDescriptor("cis/kubernetes", "kubernetes", "compliance"),
    RouteDescriptor("nis2/aws", "aws", "compliance"),
    RouteDescriptor("nis2/azure", "azure", "compliance"),
    RouteDescriptor("nis2/gcp", "gcp", "compliance"),
    RouteDescriptor("iso27001/aws", "aws", "compliance"),
    RouteDescriptor("iso27001/azure", "azure", "compliance"),
    RouteDescriptor("iso27001/gcp", "gcp", "compliance"),
    RouteDescriptor("iso27001/kubernetes", "kubernetes", "compliance"),
    RouteDescriptor("mitre/aws", "aws", "compliance"),
    RouteDescriptor("mitre/azure", "azure", "compliance"),
    RouteDescriptor("mitre/gcp", "gcp", "compliance"),
    RouteDescriptor("aws/select-service", "aws", "service"),
    RouteDescriptor("aws/select-compliance", "aws", "compliance"),
    RouteDescriptor("azure/select-service", "azure", "service"),
    RouteDescriptor("azure/select-compliance", "azure", "compliance"),
    RouteDescriptor("gcp/select-service", "gcp", "service"),
    RouteDescriptor("gcp/select-compliance", "gcp", "compliance"),
)
