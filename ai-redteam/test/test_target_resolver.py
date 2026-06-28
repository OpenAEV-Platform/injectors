import os
from unittest import TestCase
from unittest.mock import MagicMock, patch

from ai_redteam.targets import target_resolver
from ai_redteam.targets.target_resolver import TargetConfig


class TargetConfigTest(TestCase):
    def test_provider_is_uppercased(self):
        self.assertEqual(
            TargetConfig(provider="openai_compatible").provider, "OPENAI_COMPATIBLE"
        )

    def test_defaults(self):
        target = TargetConfig()
        self.assertEqual(target.provider, "OPENAI_COMPATIBLE")
        self.assertEqual(target.modality, "TEXT")
        self.assertEqual(target.configuration, {})
        self.assertIsNone(target.api_key)

    @patch.dict(os.environ, {"MY_SECRET_VAR": "resolved-secret"}, clear=False)
    def test_api_key_resolved_from_environment(self):
        target = TargetConfig(api_key_variable="MY_SECRET_VAR")
        self.assertEqual(target.api_key, "resolved-secret")


class ResolveTargetTest(TestCase):
    def test_inline_definition_when_no_target_ref(self):
        content = {
            "target_provider": "ANTHROPIC",
            "target_endpoint": "https://api.anthropic.com",
            "target_model": "claude",
        }
        target = target_resolver.resolve_target(content, api=MagicMock())
        self.assertEqual(target.provider, "ANTHROPIC")
        self.assertEqual(target.endpoint, "https://api.anthropic.com")

    def test_fetches_ai_target_asset_by_id(self):
        api = MagicMock()
        api.http_get.return_value = {
            "ai_target_provider": "OLLAMA",
            "ai_target_endpoint": "http://localhost:11434",
            "ai_target_model": "llama3",
        }
        content = {"ai_target": "asset-123"}
        target = target_resolver.resolve_target(content, api=api)
        api.http_get.assert_called_once_with("/ai_targets/asset-123")
        self.assertEqual(target.provider, "OLLAMA")
        self.assertEqual(target.model, "llama3")

    def test_inline_system_prompt_overrides_asset(self):
        api = MagicMock()
        api.http_get.return_value = {
            "ai_target_provider": "OLLAMA",
            "ai_target_system_prompt": "asset prompt",
        }
        content = {"ai_target": "asset-123", "system_prompt": "inline prompt"}
        target = target_resolver.resolve_target(content, api=api)
        self.assertEqual(target.system_prompt, "inline prompt")

    def test_falls_back_to_inline_on_fetch_error(self):
        api = MagicMock()
        api.http_get.side_effect = RuntimeError("boom")
        logger = MagicMock()
        content = {"ai_target": "asset-123", "target_provider": "OLLAMA"}
        target = target_resolver.resolve_target(content, api=api, logger=logger)
        self.assertEqual(target.provider, "OLLAMA")
        logger.warning.assert_called_once()
