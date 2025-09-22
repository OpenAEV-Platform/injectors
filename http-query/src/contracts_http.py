from typing import List

from pyobas.contracts import ContractBuilder
from pyobas.contracts.contract_config import (
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

TYPE = "openbas_http"
HTTP_RAW_POST_CONTRACT = "5948c96c-4064-4c0d-b079-51ec33f31b91"
HTTP_RAW_PUT_CONTRACT = "bb503f7c-1f17-49e1-ac31-f4c2e99fd704"
HTTP_FORM_POST_CONTRACT = "a4794081-ccb5-41ef-9855-304ad5fdf4a9"
HTTP_FORM_PUT_CONTRACT = "d11d7694-29d1-4c1a-b1d7-9fc4251f0466"
HTTP_GET_CONTRACT = "611f223d-0e95-4f5b-ad89-a09ec2be50ae"


class HttpContracts:

    @staticmethod
    def build_contract():
        # Config
        contract_config = ContractConfig(
            type=TYPE,
            label={
                SupportedLanguage.en: "HTTP Request",
                SupportedLanguage.fr: "Requête HTTP",
            },
            color_dark="#00bcd4",
            color_light="#00bcd4",
            expose=True,
        )
        # Output
        output = ContractOutputElement(
            type=ContractOutputType.Text,
            field="url",
            isMultiple=False,
            isFindingCompatible=False,
            labels=["remote"],
        )
        # Fields
        basic_auth_field = ContractCheckbox(
            key="basicAuth",
            label="Use basic authentication",
            defaultValue=False,
            mandatory=False,
        )
        username_field = ContractText(
            key="basicUser",
            label="Username",
            defaultValue="",
            mandatory=False,
            mandatoryConditionFields=[basic_auth_field.key],
            mandatoryConditionValues={basic_auth_field.key: True},
            visibleConditionFields=[basic_auth_field.key],
            visibleConditionValues={basic_auth_field.key: True},
        )
        basic_password = ContractText(
            key="basicPassword",
            label="Password",
            defaultValue="",
            mandatory=False,
            mandatoryConditionFields=[basic_auth_field.key],
            mandatoryConditionValues={basic_auth_field.key: True},
            visibleConditionFields=[basic_auth_field.key],
            visibleConditionValues={basic_auth_field.key: True},
        )
        auth_fields = [basic_auth_field, username_field, basic_password]
        # Post contract raw
        raw_post_fields: List[ContractElement] = (
            ContractBuilder()
            .mandatory(ContractText(key="uri", label="URL"))
            .add_fields(auth_fields)
            .optional(ContractTuple(key="headers", label="Headers"))
            .mandatory(ContractTextArea(key="body", label="Raw request data"))
            .build_fields()
        )
        outputs: List[ContractOutputElement] = (
            ContractBuilder().add_outputs([output]).build_outputs()
        )
        raw_post_contract = Contract(
            contract_id=HTTP_RAW_POST_CONTRACT,
            config=contract_config,
            label={
                SupportedLanguage.en: "HTTP Request - POST (raw body)",
                SupportedLanguage.fr: "Requête HTTP - POST (body brut)",
            },
            fields=raw_post_fields,
            outputs=outputs,
            manual=False,
        )
        raw_put_contract = Contract(
            contract_id=HTTP_RAW_PUT_CONTRACT,
            config=contract_config,
            label={
                SupportedLanguage.en: "HTTP Request - PUT (raw body)",
                SupportedLanguage.fr: "Requête HTTP - PUT (body brut)",
            },
            fields=raw_post_fields,
            outputs=outputs,
            manual=False,
        )
        # Post contract form
        attachment_field = ContractAttachment(
            key="attachments",
            label="Attachments",
            cardinality=ContractCardinality.Multiple,
        )
        form_post_fields: List[ContractElement] = (
            ContractBuilder()
            .mandatory(ContractText(key="uri", label="URL"))
            .add_fields(auth_fields)
            .optional(ContractTuple(key="headers", label="Headers"))
            .optional(
                ContractTuple(
                    key="parts",
                    label="Form request data",
                    attachmentKey=attachment_field.key,
                )
            )
            .optional(attachment_field)
            .build_fields()
        )
        form_post_contract = Contract(
            contract_id=HTTP_FORM_POST_CONTRACT,
            config=contract_config,
            label={
                SupportedLanguage.en: "HTTP Request - POST (key/value)",
                SupportedLanguage.fr: "Requête HTTP - POST (clé/valeur)",
            },
            fields=form_post_fields,
            outputs=outputs,
            manual=False,
        )
        form_put_contract = Contract(
            contract_id=HTTP_FORM_PUT_CONTRACT,
            config=contract_config,
            label={
                SupportedLanguage.en: "HTTP Request - PUT (key/value)",
                SupportedLanguage.fr: "Requête HTTP - PUT (clé/valeur)",
            },
            fields=form_post_fields,
            outputs=outputs,
            manual=False,
        )
        # Get contract
        get_fields: List[ContractElement] = (
            ContractBuilder()
            .mandatory(ContractText(key="uri", label="URL"))
            .add_fields(auth_fields)
            .optional(ContractTuple(key="headers", label="Headers"))
            .build_fields()
        )
        get_contract = Contract(
            contract_id=HTTP_GET_CONTRACT,
            config=contract_config,
            label={
                SupportedLanguage.en: "HTTP Request - GET",
                SupportedLanguage.fr: "Requête HTTP - GET",
            },
            fields=get_fields,
            outputs=outputs,
            manual=False,
        )
        return prepare_contracts(
            [
                raw_post_contract,
                form_post_contract,
                raw_put_contract,
                form_put_contract,
                get_contract,
            ]
        )
