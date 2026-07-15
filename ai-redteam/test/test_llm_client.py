from unittest import TestCase
from unittest.mock import MagicMock, patch

from ai_redteam.targets import llm_client
from ai_redteam.targets.target_resolver import TargetConfig


def _target(provider, endpoint=None, configuration=None):
    target = TargetConfig(
        provider=provider,
        endpoint=endpoint,
        model="test-model",
        configuration=configuration or {},
    )
    target.api_key = "secret-key"
    return target


def _response(payload, status_code=200, text="raw-text"):
    resp = MagicMock()
    resp.json.return_value = payload
    resp.status_code = status_code
    resp.text = text
    return resp


class SendPromptTest(TestCase):
    @patch("ai_redteam.targets.llm_client.requests.post")
    def test_openai_compatible_parses_choices(self, post):
        post.return_value = _response({"choices": [{"message": {"content": "hello"}}]})
        target = _target("OPENAI_COMPATIBLE", "https://api.example.com/v1")
        result = llm_client.send_prompt(target, "hi", "marker-1", timeout=5)
        self.assertEqual(result.text, "hello")
        self.assertEqual(result.status_code, 200)
        # canary marker header must always be sent
        sent_headers = post.call_args.kwargs["headers"]
        self.assertEqual(sent_headers["X-OAEV-Inject-Marker"], "marker-1")
        self.assertEqual(sent_headers["Authorization"], "Bearer secret-key")

    @patch("ai_redteam.targets.llm_client.requests.post")
    def test_azure_uses_api_key_header(self, post):
        post.return_value = _response({"choices": [{"message": {"content": "x"}}]})
        target = _target("AZURE_OPENAI", "https://azure.example.com")
        llm_client.send_prompt(target, "hi", "m", timeout=5)
        self.assertEqual(post.call_args.kwargs["headers"]["api-key"], "secret-key")

    @patch("ai_redteam.targets.llm_client.requests.post")
    def test_anthropic_joins_content_blocks(self, post):
        post.return_value = _response({"content": [{"text": "foo"}, {"text": "bar"}]})
        target = _target("ANTHROPIC", "https://api.anthropic.com")
        result = llm_client.send_prompt(target, "hi", "m", timeout=5)
        self.assertEqual(result.text, "foobar")

    @patch("ai_redteam.targets.llm_client.requests.post")
    def test_ollama_reads_message_content(self, post):
        post.return_value = _response({"message": {"content": "ollama-says"}})
        target = _target("OLLAMA", "http://localhost:11434")
        result = llm_client.send_prompt(target, "hi", "m", timeout=5)
        self.assertEqual(result.text, "ollama-says")

    @patch("ai_redteam.targets.llm_client.requests.post")
    def test_huggingface_reads_generated_text(self, post):
        post.return_value = _response([{"generated_text": "hf-out"}])
        target = _target("HUGGINGFACE", "https://hf.example.com/model")
        result = llm_client.send_prompt(target, "hi", "m", timeout=5)
        self.assertEqual(result.text, "hf-out")

    def test_huggingface_without_endpoint_raises(self):
        target = _target("HUGGINGFACE", endpoint=None)
        with self.assertRaises(ValueError):
            llm_client.send_prompt(target, "hi", "m", timeout=5)

    @patch("ai_redteam.targets.llm_client.requests.post")
    def test_custom_http_reads_configured_output_field(self, post):
        post.return_value = _response({"answer": "custom-out"})
        target = _target(
            "CUSTOM_HTTP",
            "https://agent.example.com",
            configuration={"output_field": "answer"},
        )
        result = llm_client.send_prompt(target, "hi", "m", timeout=5)
        self.assertEqual(result.text, "custom-out")

    def test_custom_http_without_endpoint_raises(self):
        target = _target("MCP_SERVER", endpoint=None)
        with self.assertRaises(ValueError):
            llm_client.send_prompt(target, "hi", "m", timeout=5)

    @patch("ai_redteam.targets.llm_client.requests.post")
    def test_custom_http_falls_back_to_json_dump(self, post):
        post.return_value = _response({"unexpected": "shape"})
        target = _target("AGENT_HTTP", "https://agent.example.com")
        result = llm_client.send_prompt(target, "hi", "m", timeout=5)
        self.assertIn("unexpected", result.text)

    @patch("ai_redteam.targets.llm_client.requests.post")
    def test_custom_http_uses_custom_auth_header(self, post):
        post.return_value = _response({"output": "ok"})
        target = _target(
            "AGENT_HTTP",
            "https://agent.example.com",
            configuration={"auth_header": "X-Api-Key", "auth_prefix": ""},
        )
        llm_client.send_prompt(target, "hi", "m", timeout=5)
        self.assertEqual(post.call_args.kwargs["headers"]["X-Api-Key"], "secret-key")

    @patch("ai_redteam.targets.llm_client.requests.post")
    def test_unknown_provider_falls_back_to_openai(self, post):
        post.return_value = _response({"choices": [{"message": {"content": "fb"}}]})
        target = _target("SOMETHING_NEW", "https://api.example.com")
        result = llm_client.send_prompt(target, "hi", "m", timeout=5)
        self.assertEqual(result.text, "fb")

    @patch("ai_redteam.targets.llm_client.requests.post")
    def test_xtm_one_posts_platform_chat_message(self, post):
        post.return_value = _response(
            {"content": "agent reply", "conversation_id": "c1"}
        )
        target = _target(
            "XTM_ONE",
            "https://xtm-one.example.test",
            configuration={"xtm_one_slug": "ctem-assistant"},
        )
        result = llm_client.send_prompt(target, "attack", "marker-9", timeout=5)
        self.assertEqual(result.text, "agent reply")
        self.assertEqual(
            post.call_args.args[0],
            "https://xtm-one.example.test/api/v1/platform/chat/messages",
        )
        sent_body = post.call_args.kwargs["json"]
        self.assertEqual(sent_body["agent_slug"], "ctem-assistant")
        self.assertEqual(sent_body["content"], "attack")
        self.assertFalse(sent_body["stream"])
        self.assertEqual(
            post.call_args.kwargs["headers"]["Authorization"], "Bearer secret-key"
        )

    @patch("ai_redteam.targets.llm_client.requests.post")
    def test_xtm_one_derives_slug_from_model_and_strips_v1(self, post):
        post.return_value = _response({"content": "ok"})
        target = _target("XTM_ONE", "https://xtm-one.example.test/v1")
        target.model = "agent:triage"
        llm_client.send_prompt(target, "hi", "m", timeout=5)
        self.assertEqual(
            post.call_args.args[0],
            "https://xtm-one.example.test/api/v1/platform/chat/messages",
        )
        self.assertEqual(post.call_args.kwargs["json"]["agent_slug"], "triage")

    def test_xtm_one_without_endpoint_raises(self):
        target = _target("XTM_ONE", endpoint=None)
        with self.assertRaises(ValueError):
            llm_client.send_prompt(target, "hi", "m", timeout=5)

    def test_xtm_one_without_slug_raises(self):
        # Neither a configured slug nor a model to derive one from.
        target = _target("XTM_ONE", "https://xtm-one.example.test")
        target.model = "   "
        with self.assertRaises(ValueError):
            llm_client.send_prompt(target, "hi", "m", timeout=5)


class SafeJsonTest(TestCase):
    def test_returns_raw_on_invalid_json(self):
        resp = MagicMock()
        resp.json.side_effect = ValueError("not json")
        resp.text = "plain body"
        self.assertEqual(llm_client._safe_json(resp), {"_raw": "plain body"})
