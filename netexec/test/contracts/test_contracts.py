from unittest import TestCase

from netexec.contracts import parse_contract_id, ParsedContractId


class ContractsTest(TestCase):

    # -- parse_contract_id: base --

    def test_parse_base_protocol(self):
        result = parse_contract_id("netexec_smb")
        self.assertEqual(result, ParsedContractId(protocol="smb", family="base", identifier=None))

    def test_parse_base_all_protocols(self):
        for proto in ("smb", "ssh", "ldap", "winrm", "mssql", "rdp", "vnc", "ftp", "wmi", "nfs"):
            result = parse_contract_id(f"netexec_{proto}")
            self.assertEqual(result.protocol, proto)
            self.assertEqual(result.family, "base")
            self.assertIsNone(result.identifier)

    # -- parse_contract_id: option --

    def test_parse_option(self):
        result = parse_contract_id("netexec_smb_opt_shares")
        self.assertEqual(result, ParsedContractId(protocol="smb", family="option", identifier="shares"))

    def test_parse_option_with_underscores_in_identifier(self):
        result = parse_contract_id("netexec_smb_opt_local_auth")
        self.assertEqual(result.identifier, "local_auth")
        self.assertEqual(result.family, "option")

    # -- parse_contract_id: module --

    def test_parse_module(self):
        result = parse_contract_id("netexec_smb_mod_spider_plus")
        self.assertEqual(result, ParsedContractId(protocol="smb", family="module", identifier="spider_plus"))

    def test_parse_module_simple_name(self):
        result = parse_contract_id("netexec_smb_mod_spooler")
        self.assertEqual(result.identifier, "spooler")
        self.assertEqual(result.family, "module")

    # -- parse_contract_id: errors --

    def test_parse_invalid_prefix_raises(self):
        with self.assertRaises(ValueError):
            parse_contract_id("nmap_smb")

    def test_parse_too_short_raises(self):
        with self.assertRaises(ValueError):
            parse_contract_id("netexec")

    def test_parse_unknown_family_raises(self):
        with self.assertRaises(ValueError):
            parse_contract_id("netexec_smb_xyz_foo")

    def test_parse_empty_string_raises(self):
        with self.assertRaises(ValueError):
            parse_contract_id("")
