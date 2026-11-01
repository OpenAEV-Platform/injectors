from unittest import TestCase

from netexec.helpers.netexec_output_parser import NetExecOutputParser

parser = NetExecOutputParser()


class NetExecOutputParserTest(TestCase):

    def setUp(self):
        self.ip = "192.168.1.1"
        self.ip_map = {"192.168.1.1": "asset-001"}

    def _make_line(self, rest, label="SMB", port="445"):
        return f"{label}  {self.ip}  {port}  WINTERFELL  {rest}"

    # ----------------------------------------------------------------
    # Empty / noise filtering
    # ----------------------------------------------------------------

    def test_parse_empty_stdout(self):
        result = parser.parse("", self.ip_map)
        self.assertEqual(result["outputs"], {})
        self.assertIn("no structured output extracted", result["message"])

    def test_parse_only_banner_lines(self):
        stdout = "\n".join(
            [
                self._make_line("[*] Windows 10 x64 (name:WINTERFELL) (domain:NORTH)"),
                self._make_line("[*] Enumeration Starting"),
            ]
        )
        result = parser.parse(stdout, self.ip_map)
        # No typed finding was extracted, but the raw stdout is still routed to
        # action_output (isFindingCompatible=False on the contract side).
        self.assertEqual(result["outputs"], {"action_output": stdout})

    def test_parse_only_auth_lines(self):
        stdout = self._make_line("[+] NORTH\\admin:P@ss (Pwn3d!)")
        result = parser.parse(stdout, self.ip_map)
        self.assertEqual(result["outputs"], {"action_output": stdout})

    def test_parse_only_error_lines(self):
        stdout = self._make_line("[-] SMB error: Connection refused")
        result = parser.parse(stdout, self.ip_map)
        self.assertEqual(result["outputs"], {"action_output": stdout})

    def test_parse_noise_lines_skipped(self):
        stdout = "\n".join(
            [
                self._make_line("[+] Found following users"),
                self._make_line("[+] Dumped 5 hashes"),
                self._make_line("[+] Enumerated shares"),
                self._make_line("----------------------------"),
                self._make_line("-ColumnName-"),
            ]
        )
        result = parser.parse(stdout, self.ip_map)
        self.assertEqual(result["outputs"], {"action_output": stdout})

    # ----------------------------------------------------------------
    # Credential parsing (SAM)
    # ----------------------------------------------------------------

    def test_parse_sam_credentials(self):
        stdout = self._make_line(
            "Administrator:500:aad3b435b51404eeaad3b435b51404ee:dbd13e1c4e338284ac4e9874f7de6ef4:::"
        )
        result = parser.parse(stdout, self.ip_map, family="option", identifier="sam")
        self.assertIn("credentials", result["outputs"])
        creds = result["outputs"]["credentials"]
        self.assertEqual(len(creds), 1)
        self.assertEqual(creds[0]["username"], "Administrator")

    def test_parse_multiple_sam_lines(self):
        stdout = "\n".join(
            [
                self._make_line(
                    "Administrator:500:aad3b435b51404eeaad3b435b51404ee:dbd13e1c4e338284ac4e9874f7de6ef4:::"
                ),
                self._make_line(
                    "Guest:501:aad3b435b51404eeaad3b435b51404ee:00000000000000000000000000000000:::"
                ),
            ]
        )
        result = parser.parse(stdout, self.ip_map, family="option", identifier="sam")
        self.assertEqual(len(result["outputs"]["credentials"]), 2)

    # ----------------------------------------------------------------
    # Asset ID mapping
    # ----------------------------------------------------------------

    def test_parse_with_asset_id_mapping(self):
        stdout = self._make_line(
            "Administrator:500:aad3b435b51404eeaad3b435b51404ee:dbd13e1c4e338284ac4e9874f7de6ef4:::"
        )
        result = parser.parse(stdout, self.ip_map, family="option", identifier="sam")
        self.assertEqual(result["outputs"]["credentials"][0]["asset_id"], "asset-001")

    def test_parse_without_asset_id_mapping(self):
        stdout = self._make_line(
            "Administrator:500:aad3b435b51404eeaad3b435b51404ee:dbd13e1c4e338284ac4e9874f7de6ef4:::"
        )
        result = parser.parse(stdout, {}, family="option", identifier="sam")
        self.assertNotIn("asset_id", result["outputs"]["credentials"][0])

    # ----------------------------------------------------------------
    # No family / identifier → no typed extraction, action_output still present
    # ----------------------------------------------------------------

    def test_parse_no_family_returns_only_action_output(self):
        stdout = self._make_line(
            "Administrator:500:aad3b435b51404eeaad3b435b51404ee:dbd13e1c4e338284ac4e9874f7de6ef4:::"
        )
        result = parser.parse(stdout, self.ip_map, family=None, identifier=None)
        self.assertEqual(result["outputs"], {"action_output": stdout})

    # ----------------------------------------------------------------
    # Mixed content
    # ----------------------------------------------------------------

    def test_parse_mixed_noise_and_findings(self):
        stdout = "\n".join(
            [
                self._make_line("[*] Windows 10 x64 (name:WINTERFELL)"),
                self._make_line("[+] NORTH\\admin:pass (Pwn3d!)"),
                self._make_line("[+] Dumped 1 hashes"),
                self._make_line(
                    "Administrator:500:aad3b435b51404eeaad3b435b51404ee:dbd13e1c4e338284ac4e9874f7de6ef4:::"
                ),
            ]
        )
        result = parser.parse(stdout, self.ip_map, family="option", identifier="sam")
        self.assertEqual(len(result["outputs"].get("credentials", [])), 1)

    # ----------------------------------------------------------------
    # Message format
    # ----------------------------------------------------------------

    def test_parse_message_contains_counts(self):
        stdout = self._make_line(
            "Administrator:500:aad3b435b51404eeaad3b435b51404ee:dbd13e1c4e338284ac4e9874f7de6ef4:::"
        )
        result = parser.parse(stdout, self.ip_map, family="option", identifier="sam")
        self.assertIn("1 credentials", result["message"])

    # ----------------------------------------------------------------
    # Robustness
    # ----------------------------------------------------------------

    def test_parse_malformed_lines_no_crash(self):
        stdout = "\n".join(
            [
                "completely random garbage line",
                "",
                "   ",
                "another line without netexec format",
                "🔥 unicode stuff ñ ü ö",
            ]
        )
        result = parser.parse(stdout, self.ip_map, family="option", identifier="sam")
        self.assertIn("message", result)
        self.assertIn("outputs", result)

    def test_parse_shares_output(self):
        stdout = "\n".join(
            [
                self._make_line("NETLOGON        READ,WRITE      Logon server share"),
                self._make_line("ADMIN$          READ,WRITE      Remote Admin"),
            ]
        )
        result = parser.parse(stdout, self.ip_map, family="option", identifier="shares")
        shares = result["outputs"].get("shares", [])
        self.assertEqual(len(shares), 1)
        self.assertEqual(shares[0]["share_name"], "NETLOGON")

    # ----------------------------------------------------------------
    # action_output: raw stdout, always routed, independent of typed dispatchers
    # ----------------------------------------------------------------

    def test_action_output_absent_for_blank_stdout(self):
        result = parser.parse("   \n  ", self.ip_map)
        self.assertNotIn("action_output", result["outputs"])

    def test_action_output_present_alongside_typed_findings(self):
        stdout = self._make_line(
            "Administrator:500:aad3b435b51404eeaad3b435b51404ee:dbd13e1c4e338284ac4e9874f7de6ef4:::"
        )
        result = parser.parse(stdout, self.ip_map, family="option", identifier="sam")
        self.assertIn("credentials", result["outputs"])
        self.assertEqual(result["outputs"]["action_output"], stdout)

    def test_action_output_preserved_on_partial_failure(self):
        # Reproduces the reported bug: a run that fails partway through (e.g. a
        # dropped SMB session) still has no typed dispatcher match, but the raw
        # stdout — including the error line — must still reach action_output so
        # it can be used as a chaining/event filter.
        stdout = "\n".join(
            [
                self._make_line(
                    "[*] Windows 10 / Server 2019 Build 17763 (name:KINGSLANDING)"
                ),
                self._make_line(
                    "[-] Failed to enumerate disks: SMB SessionError: STATUS_USER_SESSION_DELETED"
                ),
            ]
        )
        result = parser.parse(stdout, self.ip_map, family="option", identifier="disks")
        self.assertEqual(result["outputs"], {"action_output": stdout})
