import json
import os
import tempfile
import unittest
from test.helpers.test_template_analysis import (
    AUTHENTICATED_TEMPLATE,
    INTRUSIVE_TEMPLATE,
    OPERATOR_VARIABLE_TEMPLATE,
    READ_ONLY_TEMPLATE,
)
from unittest.mock import MagicMock

from nuclei.nuclei_contracts.external_contracts import ExternalContractsManager


class TemplateMetadataContractsTest(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        os.environ["NUCLEI_TEMPLATES_DIR"] = self._dir.name
        self.manager = ExternalContractsManager(MagicMock(), "injector", MagicMock())

    def tearDown(self):
        del os.environ["NUCLEI_TEMPLATES_DIR"]
        self._dir.cleanup()

    def _content(self, template_id, text):
        name = template_id + ".yaml"
        with open(os.path.join(self._dir.name, name), "w", encoding="utf-8") as f:
            f.write(text)
        created = self.manager.make_contract_create(
            "contract-id", {"ID": template_id, "file_path": name}
        )
        return json.loads(created["contract_content"])

    def test_authenticated_contract_asks_credentials_and_flags_it(self):
        content = self._content("CVE-2024-9264", AUTHENTICATED_TEMPLATE)
        credential = [
            f for f in content["fields"] if f["type"] == "credential-reference"
        ]
        self.assertEqual(len(credential), 1)
        self.assertEqual(credential[0]["credential_reference_type"], "IDENTITY")
        metadata = content["template_metadata"]
        self.assertTrue(metadata["authenticated"])
        self.assertEqual(metadata["required_variables"], ["username", "password"])
        self.assertTrue(metadata["prerequisites"])

    def test_read_only_contract_has_no_inputs(self):
        content = self._content("CVE-0000-0001", READ_ONLY_TEMPLATE)
        keys = [f["key"] for f in content["fields"]]
        self.assertNotIn("credential_reference", keys)
        self.assertFalse([k for k in keys if k.startswith("var_")])
        self.assertTrue(content["template_metadata"]["read_only"])
        self.assertFalse(content["template_metadata"]["authenticated"])

    def test_exploit_contract_is_intrusive(self):
        content = self._content("CVE-2020-11978", INTRUSIVE_TEMPLATE)
        self.assertTrue(content["template_metadata"]["intrusive"])
        self.assertFalse(content["template_metadata"]["read_only"])

    def test_operator_variable_becomes_a_contract_field(self):
        content = self._content("CVE-0000-0002", OPERATOR_VARIABLE_TEMPLATE)
        self.assertIn("var_api_token", [f["key"] for f in content["fields"]])

    def test_unreadable_template_keeps_the_plain_contract(self):
        created = self.manager.make_contract_create(
            "contract-id", {"ID": "CVE-0000-0003", "file_path": "absent.yaml"}
        )
        self.assertNotIn("template_metadata", json.loads(created["contract_content"]))


if __name__ == "__main__":
    unittest.main()
