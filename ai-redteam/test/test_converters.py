import base64
from unittest import TestCase

from ai_redteam.engines.base import apply_converter


class ApplyConverterTest(TestCase):
    def test_none_returns_input_unchanged(self):
        self.assertEqual(apply_converter("hello", "none"), "hello")
        self.assertEqual(apply_converter("hello", ""), "hello")

    def test_unknown_converter_returns_input_unchanged(self):
        self.assertEqual(apply_converter("hello", "does-not-exist"), "hello")

    def test_base64_round_trips(self):
        encoded = apply_converter("hello", "base64")
        self.assertEqual(base64.b64decode(encoded).decode("utf-8"), "hello")

    def test_rot13_is_reversible(self):
        encoded = apply_converter("hello", "rot13")
        self.assertNotEqual(encoded, "hello")
        self.assertEqual(apply_converter(encoded, "rot13"), "hello")

    def test_reverse(self):
        self.assertEqual(apply_converter("abc", "reverse"), "cba")

    def test_leetspeak(self):
        self.assertEqual(apply_converter("aeiost", "leetspeak"), "431057")

    def test_is_case_insensitive_on_converter_name(self):
        self.assertEqual(apply_converter("abc", "REVERSE"), "cba")
