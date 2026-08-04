"""Tests that credential/port fields carry the right ``argumentType``.

netexec's suite mocks ``pyoaev.contracts.contract_config`` wholesale (see
test/conftest.py), so we can't assert against the real ``PrimitiveType`` enum.
Instead we patch ``ContractText`` in the module under test and inspect the
kwargs it receives, comparing ``argumentType`` against the same mocked
``PrimitiveType`` members the production code uses.
"""

from unittest import TestCase
from unittest.mock import patch

from netexec.contracts import base_fields


def _kwargs_by_key(mock_contract_text):
    """Map each ContractText(key=...) call to its keyword arguments."""
    return {
        call.kwargs["key"]: call.kwargs for call in mock_contract_text.call_args_list
    }


class CredentialFieldArgumentTypeTest(TestCase):

    def test_typed_credentials_get_matching_primitive(self):
        """username/password/hash carry their PrimitiveType on a protocol that exposes them."""
        with patch.object(base_fields, "ContractText") as mock_ct:
            base_fields.build_credential_fields("smb")
        kwargs = _kwargs_by_key(mock_ct)
        self.assertIs(
            kwargs["username"]["argumentType"], base_fields.PrimitiveType.Username
        )
        self.assertIs(
            kwargs["password"]["argumentType"], base_fields.PrimitiveType.Password
        )
        self.assertIs(kwargs["hash"]["argumentType"], base_fields.PrimitiveType.Hash)

    def test_domain_is_left_untyped(self):
        """domain intentionally has no argumentType (no confirmed primitive fit)."""
        with patch.object(base_fields, "ContractText") as mock_ct:
            base_fields.build_credential_fields("smb")
        kwargs = _kwargs_by_key(mock_ct)
        self.assertIn("domain", kwargs)
        self.assertIsNone(kwargs["domain"]["argumentType"])

    def test_key_file_is_left_untyped(self):
        """key_file is a path on the injector host, not a discovered artifact."""
        with patch.object(base_fields, "ContractText") as mock_ct:
            base_fields.build_credential_fields("ssh")
        kwargs = _kwargs_by_key(mock_ct)
        self.assertIn("key_file", kwargs)
        self.assertIsNone(kwargs["key_file"]["argumentType"])


class PortFieldArgumentTypeTest(TestCase):

    def test_port_field_is_typed_as_port(self):
        with patch.object(base_fields, "ContractText") as mock_ct:
            base_fields.build_port_field("smb")
        kwargs = mock_ct.call_args.kwargs
        self.assertEqual(kwargs["key"], "port")
        self.assertIs(kwargs["argumentType"], base_fields.PrimitiveType.Port)
