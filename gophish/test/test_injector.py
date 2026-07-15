import json
import os
from unittest import TestCase
from unittest.mock import MagicMock, mock_open, patch

import gophish_injector.openaev_gophish as mod
from gophish_injector.client.gophish_client import CampaignResult
from gophish_injector.contracts_gophish import GOPHISH_CAMPAIGN_CONTRACT

BASE_ENV = {
    "OPENAEV_URL": "http://localhost:3001",
    "OPENAEV_TOKEN": "token",
    "INJECTOR_ID": "gophish--test",
    "GOPHISH_API_KEY": "gophish-key",
}


def make_injector():
    with patch.dict(os.environ, BASE_ENV, clear=False), patch.object(
        mod, "OpenAEVInjectorHelper"
    ), patch.object(mod, "OpenAEVConfigHelper"), patch.object(
        mod, "intercept_dump_argument"
    ), patch.object(
        mod, "open", mock_open(read_data=b"icon"), create=True
    ):
        injector = mod.OpenAEVGophish()
    injector.helper = MagicMock()
    return injector


def _data(content):
    return {
        "injection": {
            "inject_id": "i1",
            "inject_injector_contract": {
                "injector_contract_id": GOPHISH_CAMPAIGN_CONTRACT
            },
            "inject_content": content,
        }
    }


CONTENT = {
    "campaign_name": "c",
    "template_name": "t",
    "page_name": "p",
    "smtp_name": "s",
    "group_name": "g",
    "url": "http://phish",
}


class ProcessMessageTest(TestCase):
    def _callback(self, injector):
        return injector.helper.api.inject.execution_callback.call_args.kwargs["data"]

    def test_success(self):
        injector = make_injector()
        injector.client = MagicMock()
        injector.client.create_campaign.return_value = CampaignResult(
            True, "launched", campaign_id=7, stats={"opened": 1}
        )
        injector.process_message(_data(CONTENT))
        callback = self._callback(injector)
        self.assertEqual(callback["execution_status"], "SUCCESS")
        structured = json.loads(callback["execution_output_structured"])
        self.assertEqual(structured, {"campaign_id": 7, "stats": {"opened": 1}})

    def test_failure(self):
        injector = make_injector()
        injector.client = MagicMock()
        injector.client.create_campaign.return_value = CampaignResult(
            False, "bad request"
        )
        injector.process_message(_data(CONTENT))
        self.assertEqual(self._callback(injector)["execution_status"], "ERROR")

    def test_missing_required_field(self):
        injector = make_injector()
        injector.client = MagicMock()
        content = {key: value for key, value in CONTENT.items() if key != "url"}
        injector.process_message(_data(content))
        callback = self._callback(injector)
        self.assertEqual(callback["execution_status"], "ERROR")
        self.assertIn("url", callback["execution_message"])
        injector.client.create_campaign.assert_not_called()

    def test_unsupported_contract(self):
        injector = make_injector()
        injector.client = MagicMock()
        data = _data(CONTENT)
        data["injection"]["inject_injector_contract"][
            "injector_contract_id"
        ] = "00000000-0000-0000-0000-000000000000"
        injector.process_message(data)
        callback = self._callback(injector)
        self.assertEqual(callback["execution_status"], "ERROR")
        self.assertIn("Unsupported injector contract", callback["execution_message"])
        injector.client.create_campaign.assert_not_called()

    def test_start_listens(self):
        injector = make_injector()
        injector.start()
        injector.helper.listen.assert_called_once()


class LoadIconTest(TestCase):
    def test_missing_icon_returns_empty_bytes(self):
        with patch.object(mod, "open", side_effect=FileNotFoundError, create=True):
            self.assertEqual(mod.OpenAEVGophish._load_icon(), b"")

    def test_present_icon_returns_bytes(self):
        with patch.object(mod, "open", mock_open(read_data=b"icon"), create=True):
            self.assertEqual(mod.OpenAEVGophish._load_icon(), b"icon")
