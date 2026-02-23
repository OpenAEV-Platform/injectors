"""Family 1 -- Base protocol contracts (one per protocol)."""

from typing import List

from pyoaev.contracts import ContractBuilder
from pyoaev.contracts.contract_config import (
    Contract,
    ContractConfig,
    ContractText,
    SupportedLanguage,
)
from pyoaev.security_domain.types import SecurityDomains

from netexec.contracts.base_fields import build_protocol_base_fields
from netexec.contracts.contract_outputs import build_outputs_for_types
from netexec.contracts.output_registry import get_base_output_types
from netexec.contracts.protocol_config import (
    PROTOCOL_CONFIGS,
    SUPPORTED_PROTOCOLS,
    build_command_template,
)


def _build_base_contract(protocol: str, config: ContractConfig) -> Contract:
    proto_config = PROTOCOL_CONFIGS[protocol]

    builder = ContractBuilder()

    # Shared base fields (credentials + port + core)
    builder.add_fields(build_protocol_base_fields(protocol))

    # Protocol-specific extra fields (command, ps_command, query, wmi_query)
    for ef in proto_config["base_extra_fields"]:
        builder.optional(ContractText(key=ef["key"], label=ef["label"]))

    contract_id = f"netexec_{protocol}"
    label_text = f"NetExec {protocol.upper()}"

    return Contract(
        contract_id=contract_id,
        config=config,
        label={
            SupportedLanguage.en: label_text,
            SupportedLanguage.fr: label_text,
        },
        fields=builder.build_fields(),
        outputs=build_outputs_for_types(get_base_output_types()),
        manual=False,
        domains=[SecurityDomains.ENDPOINT.value, SecurityDomains.NETWORK.value],
    )


def build_base_contracts(config: ContractConfig) -> List[Contract]:
    """Generate one base contract per supported protocol."""
    return [_build_base_contract(proto, config) for proto in SUPPORTED_PROTOCOLS]
