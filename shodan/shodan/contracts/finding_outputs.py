"""Finding-compatible contract outputs for the Shodan injector.

Shodan already retrieves ports, IPs, hostnames and CVEs for every query, but
historically rendered them into a display table only, declaring a single
non-finding-compatible ``Asset`` output. These builders expose that same data as
finding-compatible ``ContractOutputElement`` so downstream attack-path chaining
can trigger off the ``IPv4``, ``PortsScan`` and ``CVE`` finding primitives,
following the nmap / netexec / censys reference pattern.

The output-dict field names below MUST stay in sync with the keys produced by
``ShodanFindingsParser`` and with the platform OutputProcessor field contracts:

- IPv4      -> primitive IPv4 string values (IPv4OutputProcessor)
- PortsScan -> ``{host, port, service, asset_id}`` (PortScanOutputProcessor)
- CVE       -> ``{id, host, severity, asset_id}`` (CVEOutputProcessor)

A declared finding type with no extractor stays empty, so these declarations are
always shipped together with ``ShodanFindingsParser``.
"""

from pyoaev.contracts.contract_config import ContractOutputElement, ContractOutputType

IPV4_FIELD = "ipv4"
PORTS_SCAN_FIELD = "ports_scan"
CVE_FIELD = "cve"


def ipv4_output() -> ContractOutputElement:
    """Build the finding-compatible IPv4 output element (primitive strings)."""
    return ContractOutputElement(
        type=ContractOutputType.IPv4,
        field=IPV4_FIELD,
        isMultiple=True,
        isFindingCompatible=True,
        labels=["shodan", "ipv4"],
    )


def ports_scan_output() -> ContractOutputElement:
    """Build the finding-compatible PortsScan output element (host/port/service)."""
    return ContractOutputElement(
        type=ContractOutputType.PortsScan,
        field=PORTS_SCAN_FIELD,
        isMultiple=True,
        isFindingCompatible=True,
        labels=["shodan", "port"],
    )


def cve_output() -> ContractOutputElement:
    """Build the finding-compatible CVE output element (id/host/severity)."""
    return ContractOutputElement(
        type=ContractOutputType.CVE,
        field=CVE_FIELD,
        isMultiple=True,
        isFindingCompatible=True,
        labels=["shodan", "cve"],
    )
