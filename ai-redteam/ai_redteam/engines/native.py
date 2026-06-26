"""Native engine: single-turn adversarial prompt sent directly to the target via the multi-provider
LLM client, with heuristic success detection. No heavy third-party dependency required."""

from ai_redteam import detectors
from ai_redteam.contracts import constants as c
from ai_redteam.engines.base import Engine, EngineResult, apply_converter
from ai_redteam.targets import llm_client


class NativeEngine(Engine):
    def __init__(self, timeout=60):
        self.timeout = timeout

    def run(self, content, target, marker, ctx) -> EngineResult:
        raw_prompt = content.get(c.KEY_ATTACK_PROMPT) or ""
        prompt = raw_prompt.replace("{marker}", marker)
        converter = content.get(c.KEY_CONVERTERS) or "none"
        if isinstance(converter, list):
            converter = converter[0] if converter else "none"
        prompt = apply_converter(prompt, converter)

        keywords_raw = content.get(c.KEY_SUCCESS_KEYWORDS) or ""
        success_keywords = [k for k in keywords_raw.split(",") if k.strip()]

        try:
            llm_response = llm_client.send_prompt(target, prompt, marker, timeout=self.timeout)
        except Exception as exc:  # noqa: BLE001
            return EngineResult(
                success=False,
                message=f"Error calling AI target: {exc}",
                status="ERROR",
            )

        response_text = llm_response.text
        verdict = detectors.evaluate(response_text, marker, success_keywords)
        success = verdict["success"]

        outputs = {
            "response": _truncate(response_text, 4000),
            "marker": marker,
            "target_endpoint": target.endpoint or "",
            "attack_succeeded": success,
        }
        if success:
            outputs["vulnerability"] = [
                {
                    "value": f"AI target vulnerable to {converter if converter != 'none' else 'direct'} attack",
                    "reason": verdict["reason"],
                }
            ]

        verdict_label = "VULNERABLE" if success else "DEFENDED"
        message = (
            f"[{verdict_label}] {verdict['reason']}.\n"
            f"HTTP status: {llm_response.status_code}\n"
            f"Converter: {converter}\n"
            f"Marker: {marker}\n\n"
            f"Prompt:\n{prompt}\n\n"
            f"Response (truncated):\n{_truncate(response_text, 1500)}"
        )
        return EngineResult(
            success=success,
            message=message,
            response=response_text,
            outputs=outputs,
            status="SUCCESS",
        )


def _truncate(text: str, length: int) -> str:
    if text is None:
        return ""
    return text if len(text) <= length else text[:length] + "... [truncated]"
