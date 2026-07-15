"""Native engine: single-turn adversarial prompt sent directly to the target via the multi-provider
LLM client, with heuristic success detection. No heavy third-party dependency required.
"""

from ai_redteam import detectors
from ai_redteam.contracts import constants as c
from ai_redteam.engines.base import Engine, EngineResult, apply_converter
from ai_redteam.targets import llm_client


class NativeEngine(Engine):
    def __init__(self, timeout=60):
        self.timeout = timeout

    def run(self, content, target, marker, ctx) -> EngineResult:
        logger = (ctx or {}).get("logger")
        raw_prompt = content.get(c.KEY_ATTACK_PROMPT) or ""
        prompt = raw_prompt.replace("{marker}", marker)
        converter = content.get(c.KEY_CONVERTERS) or "none"
        if isinstance(converter, list):
            converter = converter[0] if converter else "none"
        prompt = apply_converter(prompt, converter)

        keywords_raw = content.get(c.KEY_SUCCESS_KEYWORDS) or ""
        success_keywords = [k for k in keywords_raw.split(",") if k.strip()]

        if logger:
            logger.info(
                f"[native] Prepared attack prompt (converter='{converter}', "
                f"len={len(prompt)}, extra_keywords={success_keywords}): {prompt!r}"
            )
            logger.info(
                f"[native] Sending prompt to target provider='{target.provider}' "
                f"endpoint='{target.endpoint or '(default)'}' model='{target.model}' "
                f"(timeout={self.timeout}s)"
            )

        try:
            llm_response = llm_client.send_prompt(
                target, prompt, marker, timeout=self.timeout, logger=logger
            )
        except Exception as exc:  # noqa: BLE001
            if logger:
                logger.error(f"[native] Error calling AI target: {exc}")
            return EngineResult(
                success=False,
                message=f"Error calling AI target: {exc}",
                status="ERROR",
            )

        if logger:
            logger.info(
                f"[native] Received response from target: "
                f"http_status={llm_response.status_code}, "
                f"response_len={len(llm_response.text or '')}"
            )

        response_text = llm_response.text

        # A non-2xx response means the attack never reached / was never processed
        # by the model (auth failure, bad endpoint, upstream error, ...). This is
        # an execution ERROR, not a "defended" verdict: we cannot conclude the
        # target resisted when we never got a model answer.
        status_code = llm_response.status_code
        if status_code is not None and not (200 <= status_code < 300):
            error_message = (
                f"AI target returned HTTP {status_code} and could not be tested.\n"
                f"Converter: {converter}\n"
                f"Marker: {marker}\n\n"
                f"Prompt:\n{prompt}\n\n"
                f"Response (truncated):\n{_truncate(response_text, 1500)}"
            )
            if logger:
                logger.error(
                    f"[native] AI target returned HTTP {status_code}; reporting "
                    f"execution error for inject {(ctx or {}).get('inject_id')}"
                )
            return EngineResult(
                success=False,
                message=error_message,
                response=response_text,
                outputs={
                    "response": _truncate(response_text, 4000),
                    "marker": marker,
                    "target_endpoint": target.endpoint or "",
                    "http_status": status_code,
                    "attack_succeeded": False,
                },
                status="ERROR",
            )

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
