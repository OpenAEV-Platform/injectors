from unittest import TestCase
from unittest.mock import MagicMock

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

    def test_token_is_used_as_api_key(self):
        target = TargetConfig(token="secret-token")
        self.assertEqual(target.token, "secret-token")
        self.assertEqual(target.api_key, "secret-token")

    def test_empty_token_means_no_api_key(self):
        target = TargetConfig(token="")
        self.assertIsNone(target.token)
        self.assertIsNone(target.api_key)

    def test_whitespace_token_means_no_api_key(self):
        target = TargetConfig(token="   ")
        self.assertIsNone(target.token)
        self.assertIsNone(target.api_key)

    def test_token_is_stripped(self):
        target = TargetConfig(token="  secret-token  ")
        self.assertEqual(target.token, "secret-token")
        self.assertEqual(target.api_key, "secret-token")


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
            "ai_target_token": "asset-token",
        }
        content = {"ai_target": "asset-123"}
        target = target_resolver.resolve_target(content, api=api)
        api.http_get.assert_called_once_with("/ai_targets/asset-123")
        self.assertEqual(target.provider, "OLLAMA")
        self.assertEqual(target.model, "llama3")
        self.assertEqual(target.token, "asset-token")
        self.assertEqual(target.api_key, "asset-token")

    def test_inline_manual_token(self):
        content = {
            "target_selector": "manual",
            "target_provider": "XTM_ONE",
            "target_endpoint": "https://xtm-one.example.test",
            "target_token": "fcp-inline",
        }
        target = target_resolver.resolve_target(content, api=MagicMock())
        self.assertEqual(target.token, "fcp-inline")
        self.assertEqual(target.api_key, "fcp-inline")

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

    def test_manual_selector_ignores_target_ref(self):
        api = MagicMock()
        content = {
            "target_selector": "manual",
            "ai_target": "asset-123",
            "target_provider": "ANTHROPIC",
            "target_endpoint": "https://api.anthropic.com",
        }
        target = target_resolver.resolve_target(content, api=api)
        api.http_get.assert_not_called()
        self.assertEqual(target.provider, "ANTHROPIC")
        self.assertEqual(target.endpoint, "https://api.anthropic.com")

    def test_ai_target_selector_fetches_asset(self):
        api = MagicMock()
        api.http_get.return_value = {
            "ai_target_provider": "OLLAMA",
            "ai_target_model": "llama3",
        }
        content = {"target_selector": "ai_target", "ai_target": "asset-123"}
        target = target_resolver.resolve_target(content, api=api)
        api.http_get.assert_called_once_with("/ai_targets/asset-123")
        self.assertEqual(target.provider, "OLLAMA")
        self.assertEqual(target.model, "llama3")


class ResolveTargetsTest(TestCase):
    def test_manual_returns_single_inline(self):
        content = {"target_selector": "manual", "target_provider": "ANTHROPIC"}
        targets = target_resolver.resolve_targets(content, data={}, api=MagicMock())
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0].provider, "ANTHROPIC")

    def test_ai_target_returns_single(self):
        api = MagicMock()
        api.http_get.return_value = {
            "ai_target_provider": "OLLAMA",
            "ai_target_model": "llama3",
            "asset_name": "Local Llama",
            "asset_id": "asset-123",
        }
        content = {"target_selector": "ai_target", "ai_target": "asset-123"}
        targets = target_resolver.resolve_targets(content, data={}, api=api)
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0].name, "Local Llama")

    def test_asset_groups_fetches_all_members_paginated(self):
        api = MagicMock()
        # Group-members endpoint returns MIXED asset types across two pages; only the
        # AI targets (asset_category == AI_TARGET) are kept, endpoints are ignored.
        api.http_post.side_effect = [
            {
                "content": [
                    {
                        "asset_id": "a1",
                        "asset_name": "T1",
                        "asset_category": "AI_TARGET",
                    },
                    {"asset_id": "e1", "asset_name": "Host", "asset_category": "HOST"},
                ],
                "last": False,
            },
            {
                "content": [
                    {
                        "asset_id": "a2",
                        "asset_name": "T2",
                        "asset_category": "AI_TARGET",
                    },
                ],
                "last": True,
            },
        ]
        # Full connection config is loaded per AI target id.
        api.http_get.side_effect = [
            {"asset_id": "a1", "asset_name": "T1", "ai_target_provider": "OLLAMA"},
            {"asset_id": "a2", "asset_name": "T2", "ai_target_provider": "ANTHROPIC"},
        ]
        content = {"target_selector": "asset-groups"}
        data = {
            "assetGroups": [{"asset_group_id": "g1", "asset_group_name": "Group 1"}]
        }
        targets = target_resolver.resolve_targets(content, data=data, api=api)
        self.assertEqual([t.asset_id for t in targets], ["a1", "a2"])
        self.assertEqual([t.provider for t in targets], ["OLLAMA", "ANTHROPIC"])
        self.assertEqual(api.http_post.call_count, 2)
        # Members come from the dynamic-aware asset-group endpoint (not a static filter).
        self.assertEqual(
            api.http_post.call_args_list[0].args[0], "/asset_groups/g1/assets/search"
        )
        # Full config is then loaded per AI target id.
        self.assertEqual(
            [call.args[0] for call in api.http_get.call_args_list],
            ["/ai_targets/a1", "/ai_targets/a2"],
        )

    def test_asset_groups_without_selection_raises(self):
        content = {"target_selector": "asset-groups"}
        with self.assertRaises(ValueError):
            target_resolver.resolve_targets(content, data={}, api=MagicMock())

    def test_asset_groups_with_no_members_raises(self):
        api = MagicMock()
        api.http_post.return_value = {"content": [], "last": True}
        content = {"target_selector": "asset-groups"}
        data = {"assetGroups": [{"asset_group_id": "g1"}]}
        with self.assertRaises(ValueError):
            target_resolver.resolve_targets(content, data=data, api=api)
