import importlib.util
from unittest import TestCase, skipUnless
from unittest.mock import MagicMock, patch

from ai_redteam.engines.base import EngineResult

_HAS_PYOAEV = importlib.util.find_spec("pyoaev") is not None

if _HAS_PYOAEV:
    from ai_redteam.openaev_ai_redteam import OpenAEVAiRedTeam


def _data(contract_id="cid", content=None):
    return {
        "injection": {
            "inject_id": "inject-1",
            "inject_injector_contract": {
                "convertedContent": {"contract_id": contract_id}
            },
            "inject_content": content if content is not None else {},
        }
    }


@skipUnless(_HAS_PYOAEV, "pyoaev is required to import the injector entrypoint")
class OpenAEVAiRedTeamTest(TestCase):
    def _injector(self, engine):
        obj = OpenAEVAiRedTeam.__new__(OpenAEVAiRedTeam)
        obj.helper = MagicMock()
        obj.engines = {"native": engine}
        obj.engine_by_contract = {"cid": "native"}
        obj.engines_timeout = 120
        return obj

    def test_resolve_engine_defaults_to_native(self):
        engine = MagicMock()
        obj = self._injector(engine)
        resolved, key = obj._resolve_engine("unknown-contract")
        self.assertIs(resolved, engine)
        self.assertEqual(key, "native")

    def test_ai_execution_returns_engine_result(self):
        engine = MagicMock()
        engine.run.return_value = EngineResult(
            success=True,
            message="done",
            outputs={"attack_succeeded": True},
            status="SUCCESS",
        )
        obj = self._injector(engine)
        result = obj.ai_execution(0.0, _data())
        self.assertEqual(result["status"], "SUCCESS")
        self.assertEqual(result["message"], "done")
        # an intermediate INFO trace must be emitted before the engine runs
        self.assertTrue(obj.helper.api.inject.execution_callback.called)

    def test_ai_execution_raises_when_no_engine(self):
        obj = self._injector(MagicMock())
        obj.engines = {}
        with self.assertRaises(ValueError):
            obj.ai_execution(0.0, _data())

    def test_process_message_reports_success(self):
        engine = MagicMock()
        engine.run.return_value = EngineResult(
            success=False, message="defended", outputs={}, status="SUCCESS"
        )
        obj = self._injector(engine)
        obj.process_message(_data())
        obj.helper.api.inject.execution_reception.assert_called_once()
        final = obj.helper.api.inject.execution_callback.call_args
        self.assertEqual(final.kwargs["data"]["execution_status"], "SUCCESS")

    def test_process_message_reports_error_on_exception(self):
        engine = MagicMock()
        engine.run.side_effect = RuntimeError("boom")
        obj = self._injector(engine)
        obj.process_message(_data())
        final = obj.helper.api.inject.execution_callback.call_args
        self.assertEqual(final.kwargs["data"]["execution_status"], "ERROR")

    def test_ai_execution_emits_per_target_trace_for_asset_backed_target(self):
        from ai_redteam.targets.target_resolver import TargetConfig

        engine = MagicMock()
        engine.run.return_value = EngineResult(
            success=True,
            message="[VULNERABLE] leaked marker",
            outputs={"response": "reply"},
            status="SUCCESS",
        )
        obj = self._injector(engine)
        target = TargetConfig(name="CTEM Assistant", asset_id="asset-42")
        with patch(
            "ai_redteam.openaev_ai_redteam.resolve_targets", return_value=[target]
        ):
            obj.ai_execution(0.0, _data())

        calls = obj.helper.api.inject.execution_callback.call_args_list
        target_calls = [
            c for c in calls if c.kwargs["data"].get("execution_context_identifiers")
        ]
        self.assertEqual(len(target_calls), 1)
        data = target_calls[0].kwargs["data"]
        self.assertEqual(data["execution_context_identifiers"], ["asset-42"])
        self.assertEqual(data["execution_action"], "command_execution")
        self.assertEqual(data["execution_status"], "SUCCESS")
        self.assertEqual(data["execution_message"], "[VULNERABLE] leaked marker")
        # Duration is this target's own engine-run time, measured per target
        # rather than derived from the inject-level start timestamp.
        self.assertIsInstance(data["execution_duration"], int)
        self.assertGreaterEqual(data["execution_duration"], 0)

    def test_ai_execution_skips_per_target_trace_for_manual_target(self):
        from ai_redteam.targets.target_resolver import TargetConfig

        engine = MagicMock()
        engine.run.return_value = EngineResult(
            success=False, message="defended", outputs={}, status="SUCCESS"
        )
        obj = self._injector(engine)
        # Inline/manual target: no asset_id, so no per-target result view exists.
        target = TargetConfig(endpoint="https://example.test", model="gpt")
        with patch(
            "ai_redteam.openaev_ai_redteam.resolve_targets", return_value=[target]
        ):
            obj.ai_execution(0.0, _data())

        calls = obj.helper.api.inject.execution_callback.call_args_list
        target_calls = [
            c for c in calls if c.kwargs["data"].get("execution_context_identifiers")
        ]
        self.assertEqual(target_calls, [])

    def test_aggregate_keys_results_by_asset_id_to_avoid_collision(self):
        from ai_redteam.targets.target_resolver import TargetConfig

        obj = OpenAEVAiRedTeam.__new__(OpenAEVAiRedTeam)
        # Two distinct assets that happen to share the same display name: keying by
        # label alone would drop one of the two per-target responses.
        targets = [
            TargetConfig(name="Shared Name", asset_id="asset-1"),
            TargetConfig(name="Shared Name", asset_id="asset-2"),
        ]
        results = [
            EngineResult(
                success=False,
                message="a",
                outputs={"response": "reply-1"},
                status="SUCCESS",
            ),
            EngineResult(
                success=True,
                message="b",
                outputs={"response": "reply-2"},
                status="SUCCESS",
            ),
        ]
        aggregated = obj._aggregate_results(targets, results)
        responses = aggregated["outputs"]["responses_by_target"]
        self.assertEqual(responses, {"asset-1": "reply-1", "asset-2": "reply-2"})
        self.assertEqual(aggregated["status"], "SUCCESS")
        self.assertTrue(aggregated["outputs"]["attack_succeeded"])
