import unittest
from unittest.mock import MagicMock, patch, sentinel

import nmap.models.data as module


class TestMessageData(unittest.TestCase):
    @patch.object(module.Targets, "extract_target_meta")
    @patch.object(module.Targets, "extract_targets")
    def test_messagedata_init(self, m_extract_targets, m_extract_target_meta):
        data = {
            "injection": {
                "inject_id": sentinel.inject_id,
                "inject_injector_contract": {
                    "injector_contract_id": sentinel.injector_contract_id,
                },
                "inject_content": {
                    module.TARGET_SELECTOR_KEY: sentinel.selector_key,
                    module.TARGET_PROPERTY_SELECTOR_KEY: sentinel.selector_property,
                    "expectations": [
                        {"expectation_type": sentinel.expectation_type_one},
                        {"expectation_type": sentinel.expectation_type_two},
                    ],
                },
            }
        }
        helper = MagicMock()

        message_data = module.MessageData(data, helper)

        self.assertEqual(message_data.inject_id, sentinel.inject_id)
        self.assertEqual(message_data.contract_id, sentinel.injector_contract_id)
        self.assertEqual(message_data.selector_key, sentinel.selector_key)
        self.assertEqual(message_data.selector_property, sentinel.selector_property)
        self.assertEqual(message_data.target_results, m_extract_targets.return_value)
        self.assertEqual(message_data.targets_meta, m_extract_target_meta.return_value)
        self.assertEqual(
            message_data.expectation_types,
            [sentinel.expectation_type_one, sentinel.expectation_type_two],
        )
        self.assertEqual(message_data.raw_data, data)
        m_extract_targets.assert_called_once_with(
            sentinel.selector_key,
            sentinel.selector_property,
            data,
            helper,
        )
        m_extract_target_meta.assert_called_once_with(
            sentinel.selector_key,
            sentinel.selector_property,
            data,
            helper,
        )

    @patch.object(module.Targets, "extract_target_meta")
    @patch.object(module.Targets, "extract_targets")
    def test_messagedata_get_targets(self, m_extract_targets, m_extract_target_meta):
        data = {
            "injection": {
                "inject_id": sentinel.inject_id,
                "inject_injector_contract": {
                    "injector_contract_id": sentinel.injector_contract_id,
                },
                "inject_content": {
                    module.TARGET_SELECTOR_KEY: sentinel.selector_key,
                    module.TARGET_PROPERTY_SELECTOR_KEY: "Automatic",
                    "expectations": [
                        {"expectation_type": sentinel.expectation_type_one},
                        {"expectation_type": sentinel.expectation_type_two},
                    ],
                },
            }
        }
        helper = MagicMock()

        message_data = module.MessageData(data, helper)

        targets = message_data.get_targets()

        self.assertEqual(targets, m_extract_targets.return_value.targets)

        m_extract_targets.return_value.targets = None

        with self.assertRaises(ValueError):
            message_data.get_targets()
