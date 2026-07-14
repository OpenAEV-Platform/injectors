import json
import os
import tempfile
from unittest import TestCase

from bloodhound_injector.contracts_bloodhound import (
    AD_COLLECTION_CONTRACT,
    BloodhoundContracts,
)
from bloodhound_injector.helpers.bloodhound_executor import BloodhoundExecutor


class ContractsTest(TestCase):
    def test_build_contract(self):
        contracts = BloodhoundContracts.build_contract()
        self.assertEqual(len(contracts), 1)
        self.assertEqual(contracts[0]["contract_id"], AD_COLLECTION_CONTRACT)

    def test_findings_outputs(self):
        content = json.loads(
            BloodhoundContracts.build_contract()[0]["contract_content"]
        )
        fields = {o["field"] for o in content["outputs"]}
        self.assertEqual(fields, {"users", "computers", "attack_paths"})


class ParsingTest(TestCase):
    def _write(self, workdir, name, payload):
        with open(os.path.join(workdir, name), "w", encoding="utf-8") as handle:
            json.dump(payload, handle)

    def test_parse_collection_extracts_names_and_paths(self):
        with tempfile.TemporaryDirectory() as workdir:
            self._write(
                workdir,
                "20260714_users.json",
                {
                    "data": [
                        {"Properties": {"name": "ADMIN@CORP", "hasspn": True}},
                        {"Properties": {"name": "BOB@CORP", "dontreqpreauth": True}},
                    ]
                },
            )
            self._write(
                workdir,
                "20260714_computers.json",
                {"data": [{"Properties": {"name": "DC01.CORP"}}]},
            )

            outputs = BloodhoundExecutor.parse_collection(workdir)

        self.assertEqual(outputs["users"], ["ADMIN@CORP", "BOB@CORP"])
        self.assertEqual(outputs["computers"], ["DC01.CORP"])
        self.assertIn("Kerberoastable: ADMIN@CORP", outputs["attack_paths"])
        self.assertIn("AS-REP roastable: BOB@CORP", outputs["attack_paths"])

    def test_parse_collection_empty(self):
        with tempfile.TemporaryDirectory() as workdir:
            self.assertEqual(BloodhoundExecutor.parse_collection(workdir), {})
