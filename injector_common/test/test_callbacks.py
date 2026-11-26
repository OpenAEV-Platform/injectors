import unittest
from unittest.mock import MagicMock, patch

import requests

from injector_common.callbacks import call_with_retry, is_transient


class _HttpError(Exception):
    def __init__(self, code):
        super().__init__(f"HTTP {code}")
        self.response_code = code


class TestCallWithRetry(unittest.TestCase):
    def setUp(self):
        self.logger = MagicMock()

    def test_transient_errors(self):
        self.assertTrue(is_transient(requests.exceptions.ConnectionError()))
        self.assertTrue(is_transient(requests.exceptions.Timeout()))
        self.assertTrue(is_transient(_HttpError(503)))
        self.assertFalse(is_transient(_HttpError(404)))
        self.assertFalse(is_transient(_HttpError(500)))
        self.assertFalse(is_transient(ValueError("bad")))
        try:
            try:
                raise requests.exceptions.ConnectionError("reset")
            except requests.exceptions.ConnectionError as inner:
                raise RuntimeError("wrapped") from inner
        except RuntimeError as wrapped:
            self.assertTrue(is_transient(wrapped))

    @patch("injector_common.callbacks.time.sleep")
    def test_retries_then_succeeds(self, m_sleep):
        call = MagicMock(
            side_effect=[requests.exceptions.ConnectionError("x"), _HttpError(502), 7]
        )
        self.assertEqual(call_with_retry(call, self.logger, "complete"), 7)
        self.assertEqual(call.call_count, 3)
        self.assertEqual([c.args[0] for c in m_sleep.call_args_list], [2, 5])
        self.assertEqual(self.logger.warning.call_count, 2)

    @patch("injector_common.callbacks.time.sleep")
    def test_bounded(self, m_sleep):
        call = MagicMock(side_effect=requests.exceptions.ConnectionError("down"))
        with self.assertRaises(requests.exceptions.ConnectionError):
            call_with_retry(call, self.logger, "complete", delays=(1, 1))
        self.assertEqual(call.call_count, 3)

    @patch("injector_common.callbacks.time.sleep")
    def test_non_transient_raises_at_once(self, m_sleep):
        for error in (_HttpError(404), _HttpError(400), RuntimeError("boom")):
            call = MagicMock(side_effect=error)
            with self.assertRaises(type(error)):
                call_with_retry(call, self.logger, "complete")
            self.assertEqual(call.call_count, 1)
        m_sleep.assert_not_called()


if __name__ == "__main__":
    unittest.main()
