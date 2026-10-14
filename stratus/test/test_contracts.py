import json
from unittest import TestCase

from pyoaev.contracts.contract_config import ContractFieldKey, ContractFieldType
from pyoaev.credential.types import CredentialType

from stratus.contracts import (
    CONTRACT_REGISTRY,
    CONTRACT_TYPE,
    CREDENTIAL_SOURCE_KEY,
    CUSTOM_TECHNIQUE_FIELD_KEY,
    build_all_contracts,
    technique_contract_id,
)
from stratus.contracts.platforms import PLATFORMS, PLATFORMS_BY_KEY
from stratus.contracts.techniques import TECHNIQUES

CREDENTIAL_REFERENCE_KEY = ContractFieldKey.CredentialReference.value

# entra-id and k8s have no dedicated platform credential type: a None value is
# intentional, the frontend then applies no credential filter.
EXPECTED_CREDENTIAL_TYPE_BY_PLATFORM = {
    "aws": CredentialType.CLOUD_AWS.value,
    "eks": CredentialType.CLOUD_AWS.value,
    "azure": CredentialType.CLOUD_AZURE.value,
    "entra-id": None,
    "gcp": CredentialType.CLOUD_GCP.value,
    "k8s": None,
}


class ContractsTest(TestCase):
    def setUp(self):
        self.contracts = build_all_contracts()
        self.by_id = {c["contract_id"]: c for c in self.contracts}
        self.content_by_id = {
            cid: json.loads(c["contract_content"]) for cid, c in self.by_id.items()
        }

    def test_one_contract_per_technique_plus_custom_per_platform(self):
        self.assertEqual(len(self.contracts), len(TECHNIQUES) + len(PLATFORMS))
        # Sanity: the catalog is large (99 techniques + 6 custom at time of writing).
        self.assertGreaterEqual(len(self.contracts), 100)

    def test_contract_ids_are_unique(self):
        ids = [c["contract_id"] for c in self.contracts]
        self.assertEqual(len(ids), len(set(ids)))

    def test_registry_covers_every_built_contract(self):
        self.assertEqual(set(self.by_id), set(CONTRACT_REGISTRY))
        self.assertEqual(len(CONTRACT_REGISTRY), len(TECHNIQUES) + len(PLATFORMS))

    def test_every_contract_shares_the_stratus_type(self):
        for content in self.content_by_id.values():
            self.assertEqual(content["config"]["type"], CONTRACT_TYPE)

    def test_technique_contract_id_is_deterministic(self):
        tid = TECHNIQUES[0].id
        self.assertEqual(technique_contract_id(tid), technique_contract_id(tid))

    def test_technique_contracts_have_no_free_form_technique_field(self):
        for technique in TECHNIQUES:
            content = self.content_by_id[technique_contract_id(technique.id)]
            field_keys = {f["key"] for f in content["fields"]}
            self.assertNotIn(CUSTOM_TECHNIQUE_FIELD_KEY, field_keys)
            self.assertIn("expectations", field_keys)

    def test_technique_contracts_expose_platform_credentials(self):
        for technique in TECHNIQUES:
            platform = PLATFORMS_BY_KEY[technique.platform]
            content = self.content_by_id[technique_contract_id(technique.id)]
            field_keys = {f["key"] for f in content["fields"]}
            for cred in platform.cred_fields:
                self.assertIn(cred.key, field_keys)

    def test_custom_contracts_expose_free_form_technique_field(self):
        for platform in PLATFORMS:
            content = self.content_by_id[platform.custom_contract_id]
            field_keys = {f["key"] for f in content["fields"]}
            self.assertIn(CUSTOM_TECHNIQUE_FIELD_KEY, field_keys)

    def test_attack_patterns_are_propagated(self):
        # Stratus tags this technique with the AWS threat catalog ATT&CK id.
        tid = "aws.credential-access.ec2-steal-instance-credentials"
        contract = self.by_id[technique_contract_id(tid)]
        self.assertIn("T1552.005", contract["contract_attack_patterns_external_ids"])

    def test_labels_are_platform_prefixed(self):
        for technique in TECHNIQUES:
            platform = PLATFORMS_BY_KEY[technique.platform]
            contract = self.by_id[technique_contract_id(technique.id)]
            self.assertTrue(
                contract["contract_labels"]["en"].startswith(platform.label + " - ")
            )

    def _credential_reference_field(self, content):
        fields = [f for f in content["fields"] if f["key"] == CREDENTIAL_REFERENCE_KEY]
        self.assertEqual(len(fields), 1)
        return fields[0]

    def test_every_contract_exposes_exactly_one_credential_reference(self):
        for content in self.content_by_id.values():
            field = self._credential_reference_field(content)
            self.assertEqual(field["type"], ContractFieldType.CredentialReference.value)

    def test_credential_reference_is_mandatory_and_single_valued(self):
        for content in self.content_by_id.values():
            field = self._credential_reference_field(content)
            self.assertFalse(field["mandatory"])
            self.assertFalse(field["multiple"])

    def test_custom_contracts_credential_reference_type_matches_platform(self):
        for platform in PLATFORMS:
            content = self.content_by_id[platform.custom_contract_id]
            field = self._credential_reference_field(content)
            self.assertEqual(
                field["credential_reference_type"],
                EXPECTED_CREDENTIAL_TYPE_BY_PLATFORM[platform.key],
            )

    def test_technique_contracts_credential_reference_type_matches_platform(self):
        for technique in TECHNIQUES:
            content = self.content_by_id[technique_contract_id(technique.id)]
            field = self._credential_reference_field(content)
            self.assertEqual(
                field["credential_reference_type"],
                EXPECTED_CREDENTIAL_TYPE_BY_PLATFORM[technique.platform],
            )

    def test_every_platform_has_an_expected_credential_type(self):
        self.assertEqual(
            {p.key for p in PLATFORMS}, set(EXPECTED_CREDENTIAL_TYPE_BY_PLATFORM)
        )

    def test_credential_reference_does_not_collide_with_platform_cred_fields(self):
        for platform in PLATFORMS:
            cred_keys = {cred.key for cred in platform.cred_fields}
            self.assertNotIn(CREDENTIAL_REFERENCE_KEY, cred_keys)

    def test_credential_source_and_reference_lead_the_credential_fields(self):
        # Without a credential type, no select: the picker follows the fields.
        for technique in TECHNIQUES:
            platform = PLATFORMS_BY_KEY[technique.platform]
            content = self.content_by_id[technique_contract_id(technique.id)]
            keys = [f["key"] for f in content["fields"]]
            cred_keys = [cred.key for cred in platform.cred_fields]
            if platform.credential_provider is None:
                expected = [*cred_keys, CREDENTIAL_REFERENCE_KEY]
            else:
                expected = [CREDENTIAL_SOURCE_KEY, CREDENTIAL_REFERENCE_KEY, *cred_keys]
            self.assertEqual(keys[: len(expected)], expected)
            self.assertLess(
                keys.index(CREDENTIAL_REFERENCE_KEY), keys.index("expectations")
            )

    def test_custom_contracts_keep_credential_reference_before_technique_field(self):
        for platform in PLATFORMS:
            content = self.content_by_id[platform.custom_contract_id]
            keys = [f["key"] for f in content["fields"]]
            self.assertLess(
                keys.index(CREDENTIAL_REFERENCE_KEY),
                keys.index(CUSTOM_TECHNIQUE_FIELD_KEY),
            )


class CredentialFieldRequirementTest(TestCase):
    """The credential source select shows the picker or the manual fields."""

    @classmethod
    def setUpClass(cls):
        cls.content_by_id = {
            c["contract_id"]: json.loads(c["contract_content"])
            for c in build_all_contracts()
        }

    def _cred_fields(self, platform):
        content = self.content_by_id[platform.custom_contract_id]
        keys = {cred.key for cred in platform.cred_fields}
        return {f["key"]: f for f in content["fields"] if f["key"] in keys}

    def _field(self, contract_id, key):
        content = self.content_by_id[contract_id]
        (field,) = [f for f in content["fields"] if f["key"] == key]
        return field

    def test_credential_fields_are_shown_with_manual_credentials_only(self):
        manual = {CREDENTIAL_SOURCE_KEY: "manual"}
        for platform in PLATFORMS:
            if platform.credential_provider is None:
                continue
            fields = self._cred_fields(platform)
            for cred in platform.cred_fields:
                with self.subTest(platform=platform.key, field=cred.key):
                    field = fields[cred.key]
                    self.assertFalse(field["mandatory"])
                    self.assertEqual(field["mandatoryGroups"], [])
                    self.assertEqual(field["visibleConditionValues"], manual)
                    expected = manual if cred.mandatory else []
                    self.assertEqual(field["mandatoryConditionValues"], expected)

    def test_credential_source_select_defaults_to_the_credential_manager(self):
        for platform in PLATFORMS:
            if platform.credential_provider is None:
                continue
            with self.subTest(platform=platform.key):
                select = self._field(platform.custom_contract_id, CREDENTIAL_SOURCE_KEY)
                self.assertEqual(select["type"], "select")
                self.assertTrue(select["mandatory"])
                self.assertEqual(select["defaultValue"], ["credential_manager"])
                self.assertEqual(
                    select["choices"],
                    {
                        "credential_manager": "Credential manager",
                        "manual": f"{platform.label} - manual credentials",
                    },
                )

    def test_reference_is_required_with_the_credential_manager_only(self):
        manager = {CREDENTIAL_SOURCE_KEY: "credential_manager"}
        for platform in PLATFORMS:
            if platform.credential_provider is None:
                continue
            with self.subTest(platform=platform.key):
                reference = self._field(
                    platform.custom_contract_id, CREDENTIAL_REFERENCE_KEY
                )
                self.assertFalse(reference["mandatory"])
                self.assertEqual(reference["visibleConditionValues"], manager)
                self.assertEqual(reference["mandatoryConditionValues"], manager)

    def test_kubernetes_has_no_credential_source_select(self):
        content = self.content_by_id[PLATFORMS_BY_KEY["k8s"].custom_contract_id]
        keys = [f["key"] for f in content["fields"]]
        self.assertNotIn(CREDENTIAL_SOURCE_KEY, keys)

    def test_kubernetes_fields_stay_mandatory(self):
        platform = PLATFORMS_BY_KEY["k8s"]
        field = self._cred_fields(platform)["kubeconfig"]
        self.assertTrue(field["mandatory"])
        self.assertEqual(field["mandatoryGroups"], [])
