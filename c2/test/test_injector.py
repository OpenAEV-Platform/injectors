import os
from unittest import TestCase
from unittest.mock import MagicMock, patch

import c2_injector.openaev_c2 as mod
from c2_injector.contracts_c2 import C2_BEACON_CONTRACT
from c2_injector.helpers.c2_executor import C2Result

BASE_ENV = {
    "OPENAEV_URL": "http://localhost:3001",
    "OPENAEV_TOKEN": "token",
    "INJECTOR_ID": "c2--test",
}


def make_injector():
    with patch.dict(os.environ, BASE_ENV, clear=False), patch.object(
        mod, "OpenAEVInjectorHelper"
    ), patch.object(mod, "OpenAEVConfigHelper"), patch.object(
        mod, "intercept_dump_argument"
    ):
        injector = mod.OpenAEVC2()
    injector.helper = MagicMock()
    return injector


def _data(content):
    return {
        "injection": {
            "inject_id": "i1",
            "inject_injector_contract": {"injector_contract_id": C2_BEACON_CONTRACT},
            "inject_content": content,
        }
    }


class ProcessMessageTest(TestCase):
    def _callback(self, injector):
        return injector.helper.api.inject.execution_callback.call_args.kwargs["data"]

    def test_missing_icon_is_optional(self):
        self.assertEqual(mod.OpenAEVC2._load_icon("c2_injector/img/icon-c2.png"), b"")

    def test_success(self):
        injector = make_injector()
        injector.executor = MagicMock()
        injector.executor.beacon.return_value = C2Result(True, "beaconed")
        injector.process_message(
            _data(
                {
                    "listener_url": "https://c2/listen",
                    "beacon_count": ["5"],
                    "interval_seconds": ["0"],
                    "jitter_percent": ["0"],
                }
            )
        )
        self.assertEqual(self._callback(injector)["execution_status"], "SUCCESS")
        injector.executor.beacon.assert_called_once()

    def test_listener_url_accepts_contract_list(self):
        injector = make_injector()
        injector.executor = MagicMock()
        injector.executor.beacon.return_value = C2Result(True, "beaconed")

        injector.process_message(
            _data(
                {
                    "listener_url": ["https://c2/listen"],
                    "beacon_count": ["5"],
                    "interval_seconds": ["0"],
                    "jitter_percent": ["0"],
                }
            )
        )

        injector.executor.beacon.assert_called_once_with(
            listener_url="https://c2/listen",
            beacon_count=5,
            interval_seconds=0.0,
            jitter_percent=0.0,
        )

    def test_defaults_when_fields_missing(self):
        injector = make_injector()
        injector.executor = MagicMock()
        injector.executor.beacon.return_value = C2Result(True, "beaconed")
        injector.process_message(_data({"listener_url": "https://c2/listen"}))
        injector.executor.beacon.assert_called_once()

    def test_missing_listener_reports_error(self):
        injector = make_injector()
        injector.executor = MagicMock()
        injector.process_message(_data({}))
        self.assertEqual(self._callback(injector)["execution_status"], "ERROR")

    def test_start_listens(self):
        injector = make_injector()
        injector.start()
        injector.helper.listen.assert_called_once()
