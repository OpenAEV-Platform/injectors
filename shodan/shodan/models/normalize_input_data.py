import re
from enum import Enum
from typing import Annotated, Literal, Union

from pydantic import BaseModel, BeforeValidator, Discriminator, field_validator

EmptyStrToFalse = Annotated[
    bool, BeforeValidator(lambda v: False if v in ("", None) else v)
]


def _parse_values(values: Union[str, list[str]]) -> list[str]:
    if isinstance(values, str):
        return [value.strip() for value in re.split(r"[,\s]+", values) if value.strip()]
    elif isinstance(values, list):
        return [v.strip() for v in values if v.strip()]
    return []


class InjectContent(BaseModel):
    expectations: list[dict]
    target_selector: str
    target_property_selector: str
    auto_create_assets: EmptyStrToFalse


class ContractFieldsCommon(InjectContent):
    hostname: list[str]
    organization: list[str] | None

    @field_validator("hostname", "organization", mode="before")
    def parse_hostname_and_organization(cls, values):
        return _parse_values(values)


class DomainDiscovery(ContractFieldsCommon):
    contract: Literal["domain_discovery"]
    pass


class CVEEnumeration(ContractFieldsCommon):
    contract: Literal["cve_enumeration"]
    pass


class CVESpecificWatchlist(ContractFieldsCommon):
    contract: Literal["cve_specific_watchlist"]
    vulnerability: list[str]

    @field_validator("vulnerability", mode="before")
    def parse_vulnerability(cls, values):
        return _parse_values(values)


class CustomQuery(InjectContent):
    contract: Literal["custom_query"]
    custom_query: str


class IPEnumeration(InjectContent):
    contract: Literal["ip_enumeration"]
    ip: list[str]

    @field_validator("ip", mode="before")
    def parse_ip(cls, values):
        return _parse_values(values)


class CriticalPortsAndExposedAdminInterface(ContractFieldsCommon):
    contract: Literal["critical_ports_and_exposed_admin_interface"]
    port: list[str]

    @field_validator("port", mode="before")
    def parse_port(cls, values):
        return _parse_values(values)


class CloudProviderAssetDiscovery(ContractFieldsCommon):
    contract: Literal["cloud_provider_asset_discovery"]
    cloud_provider: list[str]

    @field_validator("cloud_provider", mode="before")
    def parse_cloud_provider(cls, values):
        return _parse_values(values)


InjectContentType = Annotated[
    Union[
        DomainDiscovery,
        CustomQuery,
        CVEEnumeration,
        CVESpecificWatchlist,
        CriticalPortsAndExposedAdminInterface,
        CloudProviderAssetDiscovery,
        IPEnumeration,
    ],
    Discriminator("contract"),
]


class ContractType(str, Enum):
    DOMAIN_DISCOVERY = "domain_discovery"
    CVE_ENUMERATION = "cve_enumeration"
    CVE_SPECIFIC_WATCHLIST = "cve_specific_watchlist"
    CUSTOM_QUERY = "custom_query"
    IP_ENUMERATION = "ip_enumeration"
    CRITICAL_PORTS_AND_EXPOSED_ADMIN_INTERFACE = (
        "critical_ports_and_exposed_admin_interface"
    )
    CLOUD_PROVIDER_ASSET_DISCOVERY = "cloud_provider_asset_discovery"


class AssetsType(BaseModel):
    asset_id: str
    endpoint_hostname: str | None
    endpoint_ips: list[str]
    endpoint_seen_ip: str | None


class TargetsType(BaseModel):
    selector_key: str
    asset_ids: list[str]
    hostnames: list[str]
    ips: list[str]
    seen_ips: list[str]
    assets: list[AssetsType]


class NormalizeInputData(BaseModel):
    contract_name: str
    contract_id: str
    inject_content: InjectContentType
    targets: TargetsType
