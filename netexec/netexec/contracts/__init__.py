"""NetExec contracts package.

Public API:
- ``build_all_contracts()``: returns all contracts for injector registration.
- ``parse_contract_id()``: parses a contract ID into protocol, family, identifier.
"""

from typing import List, NamedTuple, Optional

from pyoaev.contracts.contract_config import (
    Contract,
    ContractConfig,
    SupportedLanguage,
    prepare_contracts,
)

from netexec.contracts.base_contracts import build_base_contracts
from netexec.contracts.module_contracts import build_module_contracts
from netexec.contracts.option_contracts import build_option_contracts

CONTRACT_TYPE = "openaev_netexec"


class ParsedContractId(NamedTuple):
    """Result of parsing a contract ID."""

    protocol: str
    family: str  # "base", "option", or "module"
    identifier: Optional[str]  # option_id or safe_module_key; None for base


def parse_contract_id(contract_id: str) -> ParsedContractId:
    """Parse a contract ID into its components.

    Formats handled::

        netexec_<protocol>                       -> base
        netexec_<protocol>_opt_<option_id>       -> option
        netexec_<protocol>_mod_<safe_module_key> -> module

    The split strategy uses ``maxsplit=2`` so that identifiers containing
    underscores (e.g. ``spider_plus``, ``local_auth``) are preserved intact.
    """
    parts = contract_id.split("_", 2)

    if len(parts) < 2 or parts[0] != "netexec":
        raise ValueError(f"Invalid contract ID format: '{contract_id}'")

    protocol = parts[1]

    if len(parts) == 2:
        return ParsedContractId(protocol=protocol, family="base", identifier=None)

    rest = parts[2]

    if rest.startswith("opt_"):
        return ParsedContractId(
            protocol=protocol, family="option", identifier=rest[4:]
        )

    if rest.startswith("mod_"):
        return ParsedContractId(
            protocol=protocol, family="module", identifier=rest[4:]
        )

    raise ValueError(f"Cannot determine contract family from ID: '{contract_id}'")


def build_all_contracts() -> List[Contract]:
    """Build and return all NetExec contracts across the three families."""
    config = ContractConfig(
        type=CONTRACT_TYPE,
        label={
            SupportedLanguage.en: "NetExec",
            SupportedLanguage.fr: "NetExec",
        },
        color_dark="#d32f2f",
        color_light="#ffcdd2",
        expose=True,
    )

    all_contracts: List[Contract] = []
    all_contracts.extend(build_base_contracts(config))
    all_contracts.extend(build_option_contracts(config))
    all_contracts.extend(build_module_contracts(config))

    return prepare_contracts(all_contracts)
