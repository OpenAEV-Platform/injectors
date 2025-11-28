from unittest import TestCase

from src.helpers.helpers import HTTPHelpers


class HTTPHelpersTest(TestCase):
    def test_parse_headers_with_string(self):
        input_str = (
            "Content-Type=application/x-www-form-urlencoded,Accept=application/json"
        )
        expected = [
            {"key": "Content-Type", "value": "application/x-www-form-urlencoded"},
            {"key": "Accept", "value": "application/json"},
        ]
        result = HTTPHelpers.parse_headers(input_str)
        self.assertEqual(result, expected)

    def test_parse_parts_with_string(self):
        input_str = "msg=test&user=alice"
        expected = [
            {"key": "msg", "value": "test"},
            {"key": "user", "value": "alice"},
        ]
        result = HTTPHelpers.parse_parts(input_str)
        self.assertEqual(result, expected)

    def test_parse_headers_empty_string(self):
        result = HTTPHelpers.parse_headers("")
        self.assertEqual(result, [])

    def test_parse_parts_empty_string(self):
        result = HTTPHelpers.parse_parts("")
        self.assertEqual(result, [])
