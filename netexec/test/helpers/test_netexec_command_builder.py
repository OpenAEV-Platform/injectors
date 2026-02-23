from unittest import TestCase

from netexec.helpers.netexec_command_builder import (
    build_command,
    build_command_version,
    extract_data_base,
    extract_data_option,
    extract_data_module,
)


class NetExecCommandBuilderTest(TestCase):

    # ----------------------------------------------------------------
    # build_command
    # ----------------------------------------------------------------

    def test_minimal_command(self):
        cmd = build_command("smb", ["192.168.1.1"])
        self.assertEqual(cmd, ["netexec", "smb", "192.168.1.1"])

    def test_multiple_targets(self):
        cmd = build_command("ldap", ["10.0.0.1", "10.0.0.2"])
        self.assertEqual(cmd, ["netexec", "ldap", "10.0.0.1", "10.0.0.2"])

    def test_empty_targets_raises(self):
        with self.assertRaises(ValueError):
            build_command("smb", [])

    def test_all_credential_types(self):
        creds = {
            "username": "admin",
            "password": "P@ss",
            "hash": "aad3b4:dbd13e",
            "domain": "NORTH",
            "key_file": "/tmp/key",
        }
        cmd = build_command("smb", ["10.0.0.1"], credentials=creds)
        self.assertIn("-u", cmd)
        self.assertIn("admin", cmd)
        self.assertIn("-p", cmd)
        self.assertIn("P@ss", cmd)
        self.assertIn("-H", cmd)
        self.assertIn("aad3b4:dbd13e", cmd)
        self.assertIn("-d", cmd)
        self.assertIn("NORTH", cmd)
        self.assertIn("--key-file", cmd)
        self.assertIn("/tmp/key", cmd)

    def test_partial_credentials(self):
        cmd = build_command("smb", ["10.0.0.1"], credentials={"username": "admin"})
        self.assertIn("-u", cmd)
        self.assertNotIn("-p", cmd)
        self.assertNotIn("-H", cmd)

    def test_empty_credentials(self):
        cmd = build_command("smb", ["10.0.0.1"], credentials=None)
        self.assertEqual(cmd, ["netexec", "smb", "10.0.0.1"])
        cmd2 = build_command("smb", ["10.0.0.1"], credentials={})
        self.assertEqual(cmd2, ["netexec", "smb", "10.0.0.1"])

    def test_falsy_credential_values_skipped(self):
        cmd = build_command("smb", ["10.0.0.1"], credentials={"username": "", "password": None})
        self.assertNotIn("-u", cmd)
        self.assertNotIn("-p", cmd)

    def test_options_list(self):
        cmd = build_command("smb", ["10.0.0.1"], options=["--shares"])
        self.assertEqual(cmd[-1], "--shares")

    def test_options_string(self):
        cmd = build_command("smb", ["10.0.0.1"], options="--shares")
        self.assertEqual(cmd[-1], "--shares")

    def test_extra_args(self):
        cmd = build_command("smb", ["10.0.0.1"], extra_args=["--port", "1433"])
        self.assertEqual(cmd[-2:], ["--port", "1433"])

    def test_full_combination_ordering(self):
        cmd = build_command(
            "smb",
            ["10.0.0.1"],
            credentials={"username": "admin", "password": "pass"},
            options=["--shares"],
            extra_args=["--timeout", "30"],
        )
        assert cmd[0] == "netexec"
        assert cmd[1] == "smb"
        assert cmd[2] == "10.0.0.1"
        u_idx = cmd.index("-u")
        shares_idx = cmd.index("--shares")
        timeout_idx = cmd.index("--timeout")
        assert u_idx < shares_idx < timeout_idx

    def test_build_command_version(self):
        self.assertEqual(build_command_version(), ["netexec", "--version"])

    # ----------------------------------------------------------------
    # Security: command injection resistance
    # ----------------------------------------------------------------

    def test_special_chars_in_password_stay_as_single_element(self):
        """Passwords with shell metacharacters must remain a single list element."""
        malicious = "P@ss;rm -rf / && echo pwned"
        cmd = build_command("smb", ["10.0.0.1"], credentials={"username": "u", "password": malicious})
        p_idx = cmd.index("-p")
        self.assertEqual(cmd[p_idx + 1], malicious)

    def test_shell_metachar_in_target_stays_as_single_element(self):
        """Targets with shell metacharacters must remain a single list element."""
        bad_target = "192.168.1.1; cat /etc/passwd"
        cmd = build_command("smb", [bad_target])
        self.assertEqual(cmd[2], bad_target)

    # ----------------------------------------------------------------
    # extract_data_base
    # ----------------------------------------------------------------

    def test_extract_base_smb_with_command(self):
        content = {"username": "admin", "password": "pass", "command": "whoami"}
        data = extract_data_base(content, "smb")
        self.assertIsNotNone(data)
        self.assertEqual(data["credentials"], {"username": "admin", "password": "pass"})
        self.assertIn("-x", data["extra_args"])
        self.assertIn("whoami", data["extra_args"])

    def test_extract_base_with_port(self):
        content = {"port": "8445"}
        data = extract_data_base(content, "smb")
        self.assertIsNotNone(data)
        self.assertEqual(data["extra_args"], ["--port", "8445"])

    def test_extract_base_empty_content_returns_none(self):
        data = extract_data_base({}, "smb")
        self.assertIsNone(data)

    # ----------------------------------------------------------------
    # extract_data_option
    # ----------------------------------------------------------------

    def test_extract_option_standard(self):
        content = {"username": "admin", "password": "pass"}
        data = extract_data_option(content, "smb", "shares")
        self.assertIsNotNone(data)
        self.assertEqual(data["options"], ["--shares"])
        self.assertNotIn("output_file", data)

    def test_extract_option_asreproast_generates_output_file(self):
        content = {"username": "admin", "password": "pass"}
        data = extract_data_option(content, "ldap", "asreproast")
        self.assertIsNotNone(data)
        self.assertIn("output_file", data)
        self.assertTrue(data["output_file"].startswith("/tmp/nxc_asreproast_"))
        self.assertTrue(data["output_file"].endswith(".txt"))
        self.assertEqual(data["options"][0], "--asreproast")
        self.assertEqual(data["options"][1], data["output_file"])

    def test_extract_option_kerberoasting_generates_output_file(self):
        content = {"username": "admin", "password": "pass"}
        data = extract_data_option(content, "ldap", "kerberoasting")
        self.assertIn("output_file", data)
        self.assertTrue(data["output_file"].startswith("/tmp/nxc_kerberoasting_"))

    # ----------------------------------------------------------------
    # extract_data_module
    # ----------------------------------------------------------------

    def test_extract_module_spooler(self):
        content = {"username": "admin", "password": "pass"}
        data = extract_data_module(content, "smb", "spooler")
        self.assertIsNotNone(data)
        self.assertIn("-M", data["extra_args"])
        self.assertIn("spooler", data["extra_args"])

    def test_extract_module_with_per_module_options(self):
        content = {
            "username": "admin",
            "password": "pass",
            "mo_coerce_plus_LISTENER": "10.0.0.5",
            "mo_coerce_plus_METHOD": "All",
        }
        data = extract_data_module(content, "smb", "coerce_plus")
        self.assertIn("-M", data["extra_args"])
        self.assertIn("-o", data["extra_args"])
        o_idx = data["extra_args"].index("-o")
        opts_after = data["extra_args"][o_idx + 1:]
        opt_strings = [o for o in opts_after if "=" in o]
        self.assertTrue(any("LISTENER=10.0.0.5" in o for o in opt_strings))
        self.assertTrue(any("METHOD=All" in o for o in opt_strings))

    def test_extract_module_with_freetext_fallback(self):
        content = {"username": "admin", "password": "pass", "module_options": "KEY1=val1 KEY2=val2"}
        data = extract_data_module(content, "smb", "spooler")
        self.assertIn("-o", data["extra_args"])

    def test_extract_module_unknown_safe_key_raises(self):
        with self.assertRaises(ValueError):
            extract_data_module({}, "smb", "nonexistent_module_xyz")
