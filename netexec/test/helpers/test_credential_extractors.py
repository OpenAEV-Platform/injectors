from unittest import TestCase

from netexec.helpers.credential_extractors import (
    extract_no_credentials,
    extract_opt_sam_credentials,
    extract_opt_lsa_credentials,
    extract_opt_ntds_credentials,
    extract_opt_users_credentials,
    extract_opt_active_users_credentials,
    extract_opt_users_usernames,
    extract_opt_active_users_usernames,
    extract_opt_rid_brute_usernames,
    extract_opt_loggedon_users_usernames,
    extract_opt_shares_shares,
    extract_opt_local_groups_groups,
    extract_opt_groups_groups,
    extract_opt_computers_computers,
    extract_opt_pass_pol_password_policy,
    extract_opt_asreproast_accounts,
    extract_opt_kerberoasting_accounts,
    extract_mod_dpapi_hash_credentials,
    extract_mod_spooler_vulnerabilities,
    extract_mod_coerce_plus_vulnerabilities,
    extract_mod_ldap_checker_vulnerabilities,
    get_credential_extractor,
    get_username_extractor,
    get_share_extractor,
    get_vulnerability_extractor,
)


class CredentialExtractorsTest(TestCase):

    def setUp(self):
        self.ip = "192.168.1.1"
        self.hostname = "WINTERFELL"
        self.ip_map = {"192.168.1.1": "asset-001"}
        self.empty_ip_map = {}

    def _lines(self, *rests):
        return [(self.ip, self.hostname, r) for r in rests]

    # ----------------------------------------------------------------
    # SAM
    # ----------------------------------------------------------------

    def test_sam_standard_hash(self):
        lines = self._lines(
            "Administrator:500:aad3b435b51404eeaad3b435b51404ee:dbd13e1c4e338284ac4e9874f7de6ef4:::"
        )
        results = extract_opt_sam_credentials(lines, self.ip_map)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["username"], "Administrator")
        self.assertEqual(results[0]["hash"], "aad3b435b51404eeaad3b435b51404ee:dbd13e1c4e338284ac4e9874f7de6ef4")
        self.assertEqual(results[0]["host"], self.ip)
        self.assertEqual(results[0]["hostname"], self.hostname)
        self.assertEqual(results[0]["asset_id"], "asset-001")

    def test_sam_no_match_returns_empty(self):
        lines = self._lines("This is not a SAM hash line")
        results = extract_opt_sam_credentials(lines, self.ip_map)
        self.assertEqual(results, [])

    def test_sam_no_asset_id_when_ip_not_in_map(self):
        lines = self._lines(
            "Administrator:500:aad3b435b51404eeaad3b435b51404ee:dbd13e1c4e338284ac4e9874f7de6ef4:::"
        )
        results = extract_opt_sam_credentials(lines, self.empty_ip_map)
        self.assertEqual(len(results), 1)
        self.assertNotIn("asset_id", results[0])

    # ----------------------------------------------------------------
    # LSA (4 formats)
    # ----------------------------------------------------------------

    def test_lsa_kerberos_aes256_key(self):
        lines = self._lines(
            "NORTH\\WINTERFELL$:aes256-cts-hmac-sha1-96:4a8f3e2b1c9d0e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f"
        )
        results = extract_opt_lsa_credentials(lines, self.ip_map)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["username"], "NORTH\\WINTERFELL$")
        self.assertIn("aes256-cts-hmac-sha1-96:", results[0]["hash"])

    def test_lsa_plain_password_hex(self):
        lines = self._lines(
            "NORTH\\WINTERFELL$:plain_password_hex:0a1b2c3d4e5f"
        )
        results = extract_opt_lsa_credentials(lines, self.ip_map)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["hash"], "plain_password_hex:0a1b2c3d4e5f")

    def test_lsa_ntlm_hash(self):
        lines = self._lines(
            "NORTH\\WINTERFELL$:aad3b435b51404eeaad3b435b51404ee:dbd13e1c4e338284ac4e9874f7de6ef4:::"
        )
        results = extract_opt_lsa_credentials(lines, self.ip_map)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["hash"], "aad3b435b51404eeaad3b435b51404ee:dbd13e1c4e338284ac4e9874f7de6ef4")

    def test_lsa_cleartext_password(self):
        lines = self._lines("NORTH\\goadmin:SecretPassword123")
        results = extract_opt_lsa_credentials(lines, self.ip_map)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["username"], "NORTH\\goadmin")
        self.assertEqual(results[0]["password"], "SecretPassword123")
        self.assertNotIn("hash", results[0])

    def test_lsa_skips_dpapi_keys(self):
        lines = self._lines("dpapi_machinekey:0xabcdef1234567890abcdef1234567890abcdef12")
        results = extract_opt_lsa_credentials(lines, self.ip_map)
        self.assertEqual(results, [])

    def test_lsa_skips_dpapi_userkey(self):
        lines = self._lines("dpapi_userkey:0xfedcba9876543210fedcba9876543210fedcba98")
        results = extract_opt_lsa_credentials(lines, self.ip_map)
        self.assertEqual(results, [])

    # ----------------------------------------------------------------
    # NTDS
    # ----------------------------------------------------------------

    def test_ntds_standard_hash(self):
        lines = self._lines(
            "goadmin:500:aad3b435b51404eeaad3b435b51404ee:dbd13e1c4e338284ac4e9874f7de6ef4:::"
        )
        results = extract_opt_ntds_credentials(lines, self.ip_map)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["username"], "goadmin")

    # ----------------------------------------------------------------
    # Users credentials (password in description)
    # ----------------------------------------------------------------

    def test_users_password_in_description(self):
        lines = self._lines(
            "samwell.tarly  2025-12-11 10:33:21  0  Samwell Tarly (Password : Heartsbane)"
        )
        results = extract_opt_users_credentials(lines, self.ip_map)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["username"], "samwell.tarly")
        self.assertEqual(results[0]["password"], "Heartsbane")

    def test_active_users_credentials_returns_empty(self):
        lines = self._lines(
            "samwell.tarly  2025-12-11 10:33:21  0  Samwell Tarly (Password : Heartsbane)"
        )
        results = extract_opt_active_users_credentials(lines, self.ip_map)
        self.assertEqual(results, [])

    # ----------------------------------------------------------------
    # Username extractors
    # ----------------------------------------------------------------

    def test_users_username_extraction(self):
        lines = self._lines(
            "goadmin                       2026-02-17 09:40:12 0       Built-in account"
        )
        results = extract_opt_users_usernames(lines, self.ip_map)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["username"], "goadmin")

    def test_active_users_username_extraction(self):
        lines = self._lines(
            "arya.stark                    2025-12-11 11:32:45 0        Arya Stark"
        )
        results = extract_opt_active_users_usernames(lines, self.ip_map)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["username"], "arya.stark")

    def test_rid_brute_extracts_only_sidtypeuser(self):
        lines = self._lines(
            "500: NORTH\\goadmin (SidTypeUser)",
            "512: NORTH\\Domain Admins (SidTypeGroup)",
        )
        results = extract_opt_rid_brute_usernames(lines, self.ip_map)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["username"], "goadmin")
        self.assertEqual(results[0]["domain"], "NORTH")
        self.assertEqual(results[0]["rid"], "500")

    def test_loggedon_users_extraction(self):
        lines = self._lines("NORTH\\goadmin                   logon_server: WINTERFELL")
        results = extract_opt_loggedon_users_usernames(lines, self.ip_map)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["username"], "goadmin")
        self.assertEqual(results[0]["domain"], "NORTH")

    # ----------------------------------------------------------------
    # Shares
    # ----------------------------------------------------------------

    def test_shares_extraction(self):
        lines = self._lines("NETLOGON        READ,WRITE      Logon server share")
        results = extract_opt_shares_shares(lines, self.ip_map)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["share_name"], "NETLOGON")
        self.assertEqual(results[0]["permissions"], "READ,WRITE")

    def test_shares_excludes_admin_shares(self):
        lines = self._lines(
            "NETLOGON        READ,WRITE      Logon server share",
            "ADMIN$          READ,WRITE      Remote Admin",
            "IPC$            READ            Remote IPC",
            "C$              READ,WRITE      Default share",
        )
        results = extract_opt_shares_shares(lines, self.ip_map)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["share_name"], "NETLOGON")

    # ----------------------------------------------------------------
    # Groups
    # ----------------------------------------------------------------

    def test_local_groups_extraction(self):
        lines = self._lines("546 - Guests")
        results = extract_opt_local_groups_groups(lines, self.ip_map)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["group_name"], "Guests")
        self.assertEqual(results[0]["rid"], "546")

    def test_groups_extraction_with_member_count(self):
        lines = self._lines("Domain Admins                            membercount: 3")
        results = extract_opt_groups_groups(lines, self.ip_map)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["group_name"], "Domain Admins")
        self.assertEqual(results[0]["member_count"], 3)

    # ----------------------------------------------------------------
    # Computers
    # ----------------------------------------------------------------

    def test_computers_extraction(self):
        lines = self._lines("WINTERFELL$")
        results = extract_opt_computers_computers(lines, self.ip_map)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["computer_name"], "WINTERFELL$")

    # ----------------------------------------------------------------
    # Password policy
    # ----------------------------------------------------------------

    def test_pass_pol_extraction(self):
        lines = self._lines("Minimum password length: 5")
        results = extract_opt_pass_pol_password_policy(lines, self.ip_map)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["key"], "Minimum password length")
        self.assertEqual(results[0]["value"], "5")

    # ----------------------------------------------------------------
    # AS-REP Roasting
    # ----------------------------------------------------------------

    def test_asreproast_extraction(self):
        lines = self._lines(
            "$krb5asrep$23$brandon.stark@NORTH.SEVENKINGDOMS.LOCAL:1ae83ac0abcdef1234"
        )
        results = extract_opt_asreproast_accounts(lines, self.ip_map)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["username"], "brandon.stark")
        self.assertIn("$krb5asrep$", results[0]["hash"])

    def test_asreproast_deduplication(self):
        line = "$krb5asrep$23$brandon.stark@NORTH.SEVENKINGDOMS.LOCAL:1ae83ac0abcdef1234"
        lines = self._lines(line, line)
        results = extract_opt_asreproast_accounts(lines, self.ip_map)
        self.assertEqual(len(results), 1)

    # ----------------------------------------------------------------
    # Kerberoasting
    # ----------------------------------------------------------------

    def test_kerberoasting_extraction(self):
        lines = self._lines(
            "$krb5tgs$23$*jon.snow$NORTH$CIFS/winterfell*$salt$hashdata1234"
        )
        results = extract_opt_kerberoasting_accounts(lines, self.ip_map)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["username"], "jon.snow")

    # ----------------------------------------------------------------
    # DPAPI hash module
    # ----------------------------------------------------------------

    def test_dpapi_hash_extraction(self):
        lines = self._lines(
            "goadmin:$DPAPImk$1*1*S-1-5-21-123456789*des3*sha1*18000*abcdef*208*deadbeef"
        )
        results = extract_mod_dpapi_hash_credentials(lines, self.ip_map)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["username"], "goadmin")
        self.assertIn("$DPAPImk$", results[0]["hash"])

    # ----------------------------------------------------------------
    # Vulnerability modules
    # ----------------------------------------------------------------

    def test_spooler_enabled_is_vulnerable(self):
        lines = self._lines("Spooler service enabled")
        results = extract_mod_spooler_vulnerabilities(lines, self.ip_map)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["name"], "Spooler")
        self.assertEqual(results[0]["status"], "VULNERABLE")

    def test_spooler_disabled_is_not_finding(self):
        lines = self._lines("Spooler service disabled")
        results = extract_mod_spooler_vulnerabilities(lines, self.ip_map)
        self.assertEqual(results, [])

    def test_coerce_plus_vulnerable(self):
        lines = self._lines("VULNERABLE, PrinterBug")
        results = extract_mod_coerce_plus_vulnerabilities(lines, self.ip_map)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["name"], "PrinterBug")
        self.assertEqual(results[0]["status"], "VULNERABLE")

    def test_coerce_plus_not_vulnerable(self):
        lines = self._lines("NOT VULNERABLE, PrinterBug")
        results = extract_mod_coerce_plus_vulnerabilities(lines, self.ip_map)
        self.assertEqual(results, [])

    def test_ldap_checker_signing_not_enforced(self):
        lines = self._lines("LDAP signing NOT enforced")
        results = extract_mod_ldap_checker_vulnerabilities(lines, self.ip_map)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["name"], "LDAP Signing")
        self.assertEqual(results[0]["status"], "VULNERABLE")

    def test_ldap_checker_signing_enforced_not_finding(self):
        lines = self._lines("LDAP signing enforced")
        results = extract_mod_ldap_checker_vulnerabilities(lines, self.ip_map)
        self.assertEqual(results, [])

    def test_ldap_checker_channel_binding_never(self):
        lines = self._lines("LDAPS channel binding is set to: Never")
        results = extract_mod_ldap_checker_vulnerabilities(lines, self.ip_map)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["name"], "LDAPS Channel Binding")

    def test_ldap_checker_channel_binding_required_not_finding(self):
        lines = self._lines("LDAPS channel binding is set to: Required")
        results = extract_mod_ldap_checker_vulnerabilities(lines, self.ip_map)
        self.assertEqual(results, [])

    # ----------------------------------------------------------------
    # Registry getters
    # ----------------------------------------------------------------

    def test_get_credential_extractor_known(self):
        extractor = get_credential_extractor("option", "sam")
        self.assertIs(extractor, extract_opt_sam_credentials)

    def test_get_credential_extractor_unknown(self):
        extractor = get_credential_extractor("option", "nonexistent")
        self.assertIsNone(extractor)

    def test_get_username_extractor_known(self):
        extractor = get_username_extractor("option", "users")
        self.assertIs(extractor, extract_opt_users_usernames)

    def test_get_share_extractor_known(self):
        extractor = get_share_extractor("option", "shares")
        self.assertIs(extractor, extract_opt_shares_shares)

    def test_get_vulnerability_extractor_known(self):
        extractor = get_vulnerability_extractor("module", "spooler")
        self.assertIs(extractor, extract_mod_spooler_vulnerabilities)

    # ----------------------------------------------------------------
    # Edge cases
    # ----------------------------------------------------------------

    def test_empty_finding_lines(self):
        for extractor in (
            extract_opt_sam_credentials,
            extract_opt_lsa_credentials,
            extract_opt_ntds_credentials,
            extract_opt_users_credentials,
            extract_opt_users_usernames,
            extract_opt_shares_shares,
            extract_opt_asreproast_accounts,
            extract_mod_spooler_vulnerabilities,
        ):
            self.assertEqual(extractor([], self.ip_map), [])

    def test_extract_no_credentials_always_empty(self):
        lines = self._lines("whatever content here", "more stuff")
        self.assertEqual(extract_no_credentials(lines, self.ip_map), [])
