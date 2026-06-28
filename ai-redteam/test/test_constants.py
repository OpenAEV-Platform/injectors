from unittest import TestCase

from ai_redteam.contracts import constants as c
from ai_redteam.engines import contract_engine_map


class TechniqueCatalogTest(TestCase):
    def test_catalog_is_not_empty(self):
        self.assertTrue(c.ALL_TECHNIQUES)
        self.assertEqual(
            len(c.ALL_TECHNIQUES),
            len(c.NATIVE_TECHNIQUES) + len(c.ENGINE_CONTRACTS),
        )

    def test_contract_ids_are_unique(self):
        ids = [t.contract_id for t in c.ALL_TECHNIQUES]
        self.assertEqual(len(ids), len(set(ids)))

    def test_every_technique_has_atlas_and_engine(self):
        valid_engines = {
            c.ENGINE_NATIVE,
            c.ENGINE_GARAK,
            c.ENGINE_PYRIT,
            c.ENGINE_PROMPTFOO,
        }
        for technique in c.ALL_TECHNIQUES:
            self.assertIn(technique.engine, valid_engines, technique.key)
            self.assertTrue(technique.atlas_ids, technique.key)

    def test_contract_engine_map_covers_all_techniques(self):
        mapping = contract_engine_map()
        for technique in c.ALL_TECHNIQUES:
            self.assertEqual(mapping[technique.contract_id], technique.engine)
