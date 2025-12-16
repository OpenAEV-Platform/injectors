from pyoaev.contracts import ContractBuilder
from pyoaev.contracts.contract_config import (
    Contract,
    ContractAttachment,
    ContractCardinality,
    ContractCheckbox,
    ContractConfig,
    ContractElement,
    ContractOutputElement,
    ContractOutputType,
    ContractText,
    ContractTextArea,
    ContractTuple,
    SupportedLanguage,
    prepare_contracts,
)

class ShodanContracts:
    text_field = ContractText(
        key="text",
        label="Labeltext",
        defaultValue="",
        mandatory=True,
    )
    my_contract_fields: list[ContractElement] = (
        ContractBuilder()
        .add_fields([text_field])
        .build_fields()
    )
    contracts = {"data": prepare_contracts([
        Contract(
            contract_id="b62a0ce2-7c43-4f78-abcd-5a92413b66cf",
            config=ContractConfig(
                type="openaev_basetest",
                label={
                    SupportedLanguage.en: "Base Test",
                    SupportedLanguage.fr: "Base Test",
                },
                color_dark="#00bcd4",
                color_light="#00bcd4",
                expose=True,
            ),
            label={
                SupportedLanguage.en: "Base Test - EN",
                SupportedLanguage.fr: "Base Test - FR",
            },
            fields=my_contract_fields,
            outputs=[],
            manual=False,
        )
    ])}