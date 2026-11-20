from unittest import TestCase
from unittest.mock import MagicMock

from pyoaev.exceptions import OpenAEVUpdateError, SignatureTransmissionError

from injector_common.inject_gone import (
    InjectGoneError,
    abort_on_inject_gone,
    inject_id_from_payload,
    is_inject_gone,
)


def _not_found() -> OpenAEVUpdateError:
    return OpenAEVUpdateError("Inject not found", 404, b"")


class IsInjectGoneTest(TestCase):
    def test_404_from_pyoaev_is_inject_gone(self):
        self.assertTrue(is_inject_gone(_not_found()))

    def test_404_wrapped_by_signature_transmission_is_inject_gone(self):
        # pyoaev re-raises a 4xx on signatures as SignatureTransmissionError.
        try:
            try:
                raise _not_found()
            except OpenAEVUpdateError as inner:
                raise SignatureTransmissionError("Client error 404") from inner
        except SignatureTransmissionError as wrapped:
            self.assertTrue(is_inject_gone(wrapped))

    def test_typed_error_is_inject_gone(self):
        self.assertTrue(is_inject_gone(InjectGoneError("inject-1")))

    def test_other_errors_are_not_inject_gone(self):
        self.assertFalse(is_inject_gone(OpenAEVUpdateError("boom", 500, b"")))
        self.assertFalse(is_inject_gone(OpenAEVUpdateError("denied", 403, b"")))
        self.assertFalse(is_inject_gone(RuntimeError("boom")))
        self.assertFalse(is_inject_gone(None))


class AbortOnInjectGoneTest(TestCase):
    def setUp(self):
        self.logger = MagicMock()
        self.data = {"injection": {"inject_id": "inject-1"}}

    def test_inject_gone_is_swallowed_with_one_log_line(self):
        with abort_on_inject_gone(self.logger, self.data):
            raise _not_found()

        self.logger.warning.assert_called_once_with("inject inject-1 deleted, aborting")
        self.logger.error.assert_not_called()

    def test_other_errors_propagate(self):
        with self.assertRaises(RuntimeError):
            with abort_on_inject_gone(self.logger, self.data):
                raise RuntimeError("boom")
        self.logger.warning.assert_not_called()

    def test_inject_id_from_payload_never_raises(self):
        self.assertEqual(inject_id_from_payload(self.data), "inject-1")
        self.assertIsNone(inject_id_from_payload({}))
        self.assertIsNone(inject_id_from_payload(None))
        self.assertIsNone(inject_id_from_payload({"injection": "x"}))
