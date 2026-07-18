import json
from unittest import TestCase

from stratus.contracts import (
    CONTRACT_TYPE,
    CUSTOM_TECHNIQUE_FIELD_KEY,
    PLATFORMS,
    PLATFORMS_BY_CONTRACT,
    TECHNIQUE_FIELD_KEY,
    build_all_contracts,
)
from stratus.contracts.platforms import (
    AWS_CONTRACT,
    AZURE_CONTRACT,
    EKS_CONTRACT,
    ENTRA_CONTRACT,
    GCP_CONTRACT,
    K8S_CONTRACT,
)


class ContractsTest(TestCase):
    def setUp(self):
        self.contracts = build_all_contracts()
        self.content_by_id = {
            c["contract_id"]: json.loads(c["contract_content"]) for c in self.contracts
        }

    def test_one_contract_per_platform(self):
        self.assertEqual(len(self.contracts), len(PLATFORMS))
        self.assertEqual(len(self.contracts), 6)

    def test_contract_ids_are_stable_and_unique(self):
        ids = {c["contract_id"] for c in self.contracts}
        self.assertEqual(
            ids,
            {
                AWS_CONTRACT,
                AZURE_CONTRACT,
                ENTRA_CONTRACT,
                GCP_CONTRACT,
                K8S_CONTRACT,
                EKS_CONTRACT,
            },
        )

    def test_every_contract_shares_the_stratus_type(self):
        for content in self.content_by_id.values():
            self.assertEqual(content["config"]["type"], CONTRACT_TYPE)

    def test_platform_index_matches_platform_list(self):
        self.assertEqual(len(PLATFORMS_BY_CONTRACT), len(PLATFORMS))
        for platform in PLATFORMS:
            self.assertIs(PLATFORMS_BY_CONTRACT[platform.contract_id], platform)

    def test_every_platform_declares_techniques(self):
        for platform in PLATFORMS:
            self.assertGreater(len(platform.techniques), 0)
            # Technique ids are namespaced by the Stratus platform prefix.
            for technique_id in platform.techniques:
                self.assertIn(".", technique_id)

    def test_each_contract_exposes_selector_and_custom_override(self):
        for content in self.content_by_id.values():
            field_keys = {f["key"] for f in content["fields"]}
            self.assertIn(TECHNIQUE_FIELD_KEY, field_keys)
            self.assertIn(CUSTOM_TECHNIQUE_FIELD_KEY, field_keys)
            self.assertIn("expectations", field_keys)

    def test_each_contract_exposes_its_credential_fields(self):
        for platform in PLATFORMS:
            content = self.content_by_id[platform.contract_id]
            field_keys = {f["key"] for f in content["fields"]}
            for cred in platform.cred_fields:
                self.assertIn(cred.key, field_keys)

    def test_selector_default_is_a_valid_choice(self):
        for platform in PLATFORMS:
            content = self.content_by_id[platform.contract_id]
            selector = next(
                f for f in content["fields"] if f["key"] == TECHNIQUE_FIELD_KEY
            )
            default = selector["defaultValue"][0]
            self.assertIn(default, platform.techniques)
            # The selector choices exactly mirror the platform catalog.
            self.assertEqual(set(selector["choices"]), set(platform.techniques))
