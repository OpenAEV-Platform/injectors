from unittest import TestCase
from unittest.mock import MagicMock, patch

from c2_injector.contracts_c2 import C2_BEACON_CONTRACT, C2Contracts
from c2_injector.helpers.c2_executor import (
    MAX_BEACONS,
    MAX_INTERVAL_SECONDS,
    C2Executor,
)


class ContractsTest(TestCase):
    def test_build_contract(self):
        contracts = C2Contracts.build_contract()
        self.assertEqual(len(contracts), 1)
        self.assertEqual(contracts[0]["contract_id"], C2_BEACON_CONTRACT)


class ExecutorTest(TestCase):
    def _executor(self):
        # no-op sleeper so tests do not wait
        return C2Executor(sleeper=lambda _seconds: None)

    @patch("c2_injector.helpers.c2_executor.requests.get")
    def test_beacon_sends_expected_count(self, mock_get):
        response = MagicMock()
        response.status_code = 200
        mock_get.return_value = response

        result = self._executor().beacon("https://c2/listen", 5, 0, 0)
        self.assertTrue(result.success)
        self.assertEqual(mock_get.call_count, 5)
        self.assertEqual(result.outputs["beacons_sent"], ["5"])
        self.assertEqual(result.outputs["beacons_reached"], ["5"])
        self.assertFalse(mock_get.call_args.kwargs["allow_redirects"])

    @patch("c2_injector.helpers.c2_executor.requests.get")
    def test_beacon_counts_blocked_as_sent(self, mock_get):
        import requests

        mock_get.side_effect = requests.ConnectionError("blocked")
        result = self._executor().beacon("https://c2/listen", 3, 0, 0)
        self.assertTrue(result.success)
        self.assertEqual(result.outputs["beacons_sent"], ["3"])
        self.assertEqual(result.outputs["beacons_reached"], ["0"])

    @patch("c2_injector.helpers.c2_executor.requests.get")
    def test_beacon_count_is_capped(self, mock_get):
        response = MagicMock()
        response.status_code = 200
        mock_get.return_value = response

        self._executor().beacon("https://c2/listen", MAX_BEACONS + 50, 0, 0)
        self.assertEqual(mock_get.call_count, MAX_BEACONS)

    @patch("c2_injector.helpers.c2_executor.random.uniform", return_value=600)
    def test_jittered_delay_is_bounded(self, mock_uniform):
        delay = C2Executor._jittered(MAX_INTERVAL_SECONDS, 1000)

        self.assertEqual(delay, MAX_INTERVAL_SECONDS)
        mock_uniform.assert_called_once_with(
            -MAX_INTERVAL_SECONDS, MAX_INTERVAL_SECONDS
        )
