from typing import List

from pyoaev.contracts import ContractBuilder
from pyoaev.contracts.contract_config import (
    Contract,
    ContractCardinality,
    ContractConfig,
    ContractElement,
    ContractExpectations,
    ContractSelect,
    ContractText,
    Expectation,
    ExpectationType,
    SupportedLanguage,
    prepare_contracts,
)
from pyoaev.security_domain.types import SecurityDomains

TYPE = "openaev_c2"

C2_BEACON_CONTRACT = "f6c7d8e9-9daa-4fb7-8ec5-ab1c2d3e4f56"

PROFILE_CHOICES = {
    "sliver_http": "Sliver HTTP(S) beacon",
    "mythic_http": "Mythic HTTP beacon",
    "generic_https": "Generic HTTPS beacon",
}


class C2Contracts:
    @staticmethod
    def build_contract():
        contract_config = ContractConfig(
            type=TYPE,
            label={
                SupportedLanguage.en: "C2 Emulation",
                SupportedLanguage.fr: "Emulation C2",
            },
            color_dark="#c92a2a",
            color_light="#c92a2a",
            expose=True,
        )

        listener_url = ContractText(
            key="listener_url",
            label="C2 listener URL",
            mandatory=True,
        )
        profile = ContractSelect(
            key="profile",
            label="Beacon profile",
            defaultValue=["sliver_http"],
            mandatory=True,
            choices=PROFILE_CHOICES,
        )
        beacon_count = ContractText(
            key="beacon_count",
            label="Number of beacons",
            mandatory=True,
            defaultValue=["10"],
        )
        interval_seconds = ContractText(
            key="interval_seconds",
            label="Interval between beacons (seconds)",
            mandatory=True,
            defaultValue=["5"],
        )
        jitter_percent = ContractText(
            key="jitter_percent",
            label="Jitter (percent)",
            mandatory=False,
            defaultValue=["20"],
        )

        expectations = ContractExpectations(
            key="expectations",
            label="Expectations",
            mandatory=False,
            cardinality=ContractCardinality.Multiple,
            predefinedExpectations=[
                Expectation(
                    expectation_type=ExpectationType.detection,
                    expectation_name="Detection",
                    expectation_description="NDR / network monitoring detects the C2.",
                    expectation_score=100,
                    expectation_expectation_group=False,
                )
            ],
        )

        fields: List[ContractElement] = (
            ContractBuilder()
            .add_fields(
                [
                    listener_url,
                    profile,
                    beacon_count,
                    interval_seconds,
                    jitter_percent,
                    expectations,
                ]
            )
            .build_fields()
        )

        contract = Contract(
            contract_id=C2_BEACON_CONTRACT,
            config=contract_config,
            label={
                SupportedLanguage.en: "C2 - Emulate beaconing",
                SupportedLanguage.fr: "C2 - Emuler le beaconing",
            },
            fields=fields,
            outputs=ContractBuilder().build_outputs(),
            manual=False,
            domains=[SecurityDomains.NETWORK.value],
        )

        return prepare_contracts([contract])
