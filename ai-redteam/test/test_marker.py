from unittest import TestCase

from ai_redteam import marker as marker_mod


class BuildMarkerTest(TestCase):
    def test_returns_non_empty_string(self):
        value = marker_mod.build_marker("inject-1")
        self.assertIsInstance(value, str)
        self.assertTrue(value)

    def test_is_deterministic(self):
        self.assertEqual(
            marker_mod.build_marker("inject-1", "agent-1"),
            marker_mod.build_marker("inject-1", "agent-1"),
        )

    def test_differs_for_different_injects(self):
        self.assertNotEqual(
            marker_mod.build_marker("inject-1"),
            marker_mod.build_marker("inject-2"),
        )


class RequestHeaderTest(TestCase):
    def test_carries_marker_header(self):
        headers = marker_mod.request_header("abc123")
        self.assertEqual(headers.get("X-OAEV-Inject-Marker"), "abc123")
