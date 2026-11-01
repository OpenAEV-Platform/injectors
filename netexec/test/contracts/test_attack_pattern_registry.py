"""Tests for the NetExec ATT&CK technique registry.

These are pure-data lookups, so they run without the real pyoaev SDK (see
test/conftest.py). They guard against accidental key renames, dropped
technique IDs, and regressions in the intentionally-empty contracts.
"""

from unittest import TestCase

from netexec.contracts.attack_pattern_registry import (
    get_base_attack_patterns,
    get_module_attack_patterns,
    get_option_attack_patterns,
)
from netexec.contracts.protocol_config import SUPPORTED_PROTOCOLS


class BaseAttackPatternsTest(TestCase):

    def test_known_base_protocols(self):
        self.assertEqual(
            get_base_attack_patterns("smb"),
            ["T1059.003", "T1059.001", "T1110.001", "T1550.002"],
        )
        self.assertEqual(get_base_attack_patterns("ssh"), ["T1059.004", "T1110.001"])
        self.assertEqual(get_base_attack_patterns("wmi"), ["T1047", "T1059.001"])

    def test_nfs_base_is_intentionally_empty(self):
        self.assertEqual(get_base_attack_patterns("nfs"), [])

    def test_every_supported_protocol_has_an_entry(self):
        """Each protocol resolves to a list (empty is allowed, missing is not)."""
        for protocol in SUPPORTED_PROTOCOLS:
            with self.subTest(protocol=protocol):
                self.assertIsInstance(get_base_attack_patterns(protocol), list)

    def test_unknown_protocol_returns_empty(self):
        self.assertEqual(get_base_attack_patterns("does_not_exist"), [])

    def test_returned_list_is_a_defensive_copy(self):
        """Mutating the returned list must not corrupt the registry."""
        first = get_base_attack_patterns("smb")
        first.append("T9999")
        self.assertNotIn("T9999", get_base_attack_patterns("smb"))


class OptionAttackPatternsTest(TestCase):

    def test_known_options(self):
        self.assertEqual(get_option_attack_patterns("sam"), ["T1003.002"])
        self.assertEqual(get_option_attack_patterns("ntds"), ["T1003.003"])
        self.assertEqual(get_option_attack_patterns("kerberoasting"), ["T1558.003"])

    def test_no_output_option_is_intentionally_empty(self):
        self.assertEqual(get_option_attack_patterns("no_output"), [])

    def test_unknown_option_returns_empty(self):
        self.assertEqual(get_option_attack_patterns("does_not_exist"), [])

    def test_returned_list_is_a_defensive_copy(self):
        first = get_option_attack_patterns("sam")
        first.append("T9999")
        self.assertNotIn("T9999", get_option_attack_patterns("sam"))


class ModuleAttackPatternsTest(TestCase):

    def test_known_modules(self):
        self.assertEqual(get_module_attack_patterns("lsassy"), ["T1003.001"])
        self.assertEqual(get_module_attack_patterns("zerologon"), ["T1210"])
        self.assertEqual(get_module_attack_patterns("spider_plus"), ["T1083", "T1005"])

    def test_test_connection_module_is_intentionally_empty(self):
        self.assertEqual(get_module_attack_patterns("test_connection"), [])

    def test_unknown_module_returns_empty(self):
        self.assertEqual(get_module_attack_patterns("does_not_exist"), [])

    def test_returned_list_is_a_defensive_copy(self):
        first = get_module_attack_patterns("lsassy")
        first.append("T9999")
        self.assertNotIn("T9999", get_module_attack_patterns("lsassy"))
