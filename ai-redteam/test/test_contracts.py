import importlib.util
from unittest import TestCase, skipUnless

from ai_redteam.contracts import constants as c

_HAS_PYOAEV = importlib.util.find_spec("pyoaev") is not None


@skipUnless(_HAS_PYOAEV, "pyoaev is required to build contracts")
class BuildContractsTest(TestCase):
    def test_builds_one_contract_per_technique(self):
        from ai_redteam.contracts.ai_contracts import build_contracts

        contracts = build_contracts()
        self.assertEqual(len(contracts), len(c.ALL_TECHNIQUES))


@skipUnless(_HAS_PYOAEV, "pyoaev is required to build contracts")
class TargetFieldsTest(TestCase):
    def _fields_by_key(self):
        from ai_redteam.contracts.ai_contracts import _target_fields

        return {f.key: f for f in _target_fields()}

    def test_type_of_targets_selector_defaults_to_ai_target(self):
        selector = self._fields_by_key()[c.KEY_TARGET_SELECTOR]
        self.assertEqual(selector.type, "select")
        self.assertTrue(selector.mandatory)
        self.assertEqual(selector.defaultValue, [c.TARGET_SELECTOR_AI_TARGET])
        self.assertEqual(
            set(selector.choices.keys()),
            {
                c.TARGET_SELECTOR_AI_TARGET,
                c.TARGET_SELECTOR_ASSET_GROUPS,
                c.TARGET_SELECTOR_MANUAL,
            },
        )

    def test_asset_group_field_visible_on_asset_groups(self):
        asset_groups = self._fields_by_key()[c.KEY_ASSET_GROUPS]
        self.assertEqual(asset_groups.type, "asset-group")
        self.assertEqual(
            asset_groups.visibleConditionValues,
            {c.KEY_TARGET_SELECTOR: c.TARGET_SELECTOR_ASSET_GROUPS},
        )

    def test_ai_target_field_is_ai_target_type_visible_on_ai_target(self):
        ai_target = self._fields_by_key()[c.KEY_TARGET_REF]
        self.assertEqual(ai_target.type, "ai-target")
        self.assertEqual(
            ai_target.visibleConditionValues,
            {c.KEY_TARGET_SELECTOR: c.TARGET_SELECTOR_AI_TARGET},
        )
        self.assertEqual(
            ai_target.mandatoryConditionValues,
            {c.KEY_TARGET_SELECTOR: c.TARGET_SELECTOR_AI_TARGET},
        )

    def test_inline_fields_are_visible_only_on_manual(self):
        fields = self._fields_by_key()
        for key in (
            c.KEY_PROVIDER,
            c.KEY_ENDPOINT,
            c.KEY_MODEL,
            c.KEY_TOKEN,
            c.KEY_SYSTEM_PROMPT,
        ):
            self.assertEqual(
                fields[key].visibleConditionValues,
                {c.KEY_TARGET_SELECTOR: c.TARGET_SELECTOR_MANUAL},
                msg=f"{key} should be visible only in manual mode",
            )
