"""Family 3 -- Protocol + module contracts (one per module per protocol)."""

from typing import List

from pyoaev.contracts import ContractBuilder
from pyoaev.contracts.contract_config import (
    Contract,
    ContractConfig,
    ContractElement,
    ContractText,
    SupportedLanguage,
)
from pyoaev.security_domain.types import SecurityDomains

from netexec.contracts.base_fields import build_protocol_base_fields
from netexec.contracts.contract_outputs import build_outputs_for_types
from netexec.contracts.output_registry import get_module_output_types
from netexec.contracts.protocol_config import SUPPORTED_PROTOCOLS, build_command_template
from netexec.modules_registry import (
    get_modules_for_protocol,
    safe_module_key,
)


def _build_module_option_fields(module: dict) -> List[ContractElement]:
    """Build the per-module option fields + free-text fallback."""
    fields: List[ContractElement] = []
    safe_name = safe_module_key(module["name"])

    for opt_name, opt_info in (module.get("options") or {}).items():
        field_key = f"mo_{safe_name}_{opt_name}"
        label = f"{opt_name}"
        if opt_info.get("desc"):
            label += f" - {opt_info['desc']}"

        fields.append(
            ContractText(
                key=field_key,
                label=label,
                mandatory=opt_info.get("required", False),
            )
        )

    # Free-text fallback for extra module options
    fields.append(
        ContractText(
            key="module_options",
            label="Additional module options (-o KEY=VALUE)",
            mandatory=False,
        )
    )

    return fields


def _build_module_contract(
    protocol: str, module: dict, config: ContractConfig
) -> Contract:
    safe_name = safe_module_key(module["name"])

    builder = ContractBuilder()
    builder.add_fields(build_protocol_base_fields(protocol))
    builder.add_fields(_build_module_option_fields(module))

    contract_id = f"netexec_{protocol}_mod_{safe_name}"
    label_text = f"NetExec {protocol.upper()} - {module['name']}"

    return Contract(
        contract_id=contract_id,
        config=config,
        label={
            SupportedLanguage.en: label_text,
            SupportedLanguage.fr: label_text,
        },
        fields=builder.build_fields(),
        outputs=build_outputs_for_types(get_module_output_types(safe_name)),
        manual=False,
        domains=[SecurityDomains.ENDPOINT.value, SecurityDomains.NETWORK.value],
    )


def build_module_contracts(config: ContractConfig) -> List[Contract]:
    """Generate one contract per (protocol, module) pair."""
    contracts: List[Contract] = []
    for protocol in SUPPORTED_PROTOCOLS:
        modules = get_modules_for_protocol(protocol)

        # Safety check: no duplicate safe keys within a protocol
        seen_keys: set = set()
        for mod in modules:
            key = safe_module_key(mod["name"])
            if key in seen_keys:
                raise ValueError(
                    f"Duplicate safe_module_key '{key}' for protocol '{protocol}'"
                )
            seen_keys.add(key)

        for mod in modules:
            contracts.append(_build_module_contract(protocol, mod, config))

    return contracts
