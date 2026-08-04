from unittest import TestCase
from unittest.mock import MagicMock

from http_query.helpers.helpers import HTTPHelpers


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

    def test_response_parsing_body_matches_response_text(self):
        response = MagicMock()
        response.url = "https://example.com"
        response.status_code = 200
        response.text = "<html>hi</html>"
        result = HTTPHelpers.response_parsing(response)
        self.assertEqual(result["body"], "<html>hi</html>")
        self.assertEqual(result["message"], "<html>hi</html>")

    def test_response_parsing_body_empty_when_no_response_text(self):
        """message falls back to a synthetic placeholder; body stays the real
        (empty) value so callers can tell the two apart."""
        response = MagicMock()
        response.url = "https://example.com"
        response.status_code = 204
        response.text = ""
        result = HTTPHelpers.response_parsing(response)
        self.assertEqual(result["body"], "")
        self.assertEqual(result["message"], "No response body (HTTP 204)")
