"""Family 2 -- Protocol + option contracts (one per option per protocol)."""

from typing import List

from pyoaev.contracts import ContractBuilder
from pyoaev.contracts.contract_config import (
    Contract,
    ContractConfig,
    SupportedLanguage,
)
from pyoaev.security_domain.types import SecurityDomains

from netexec.contracts.base_fields import build_protocol_base_fields
from netexec.contracts.contract_outputs import build_outputs_for_types
from netexec.contracts.output_registry import get_option_output_types
from netexec.contracts.protocol_config import (
    PROTOCOL_CONFIGS,
    SUPPORTED_PROTOCOLS,
    build_command_template,
)


def _build_option_contract(
    protocol: str, option: dict, config: ContractConfig
) -> Contract:
    builder = ContractBuilder()
    builder.add_fields(build_protocol_base_fields(protocol))

    contract_id = f"netexec_{protocol}_opt_{option['id']}"
    label_text = f"NetExec {protocol.upper()} - {option['label']}"

    return Contract(
        contract_id=contract_id,
        config=config,
        label={
            SupportedLanguage.en: label_text,
            SupportedLanguage.fr: label_text,
        },
        fields=builder.build_fields(),
        outputs=build_outputs_for_types(get_option_output_types(option["id"])),
        manual=False,
        domains=[SecurityDomains.ENDPOINT.value, SecurityDomains.NETWORK.value],
    )


def build_option_contracts(config: ContractConfig) -> List[Contract]:
    """Generate one contract per (protocol, option) pair."""
    contracts: List[Contract] = []
    for protocol in SUPPORTED_PROTOCOLS:
        proto_config = PROTOCOL_CONFIGS[protocol]
        for option in proto_config["options"]:
            contracts.append(_build_option_contract(protocol, option, config))
    return contracts
