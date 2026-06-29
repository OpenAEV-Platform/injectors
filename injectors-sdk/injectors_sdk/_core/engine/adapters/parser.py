"""Default output parsing implementation."""

import json
import re
from typing import Any

from pydantic import BaseModel, ValidationError

from injectors_sdk._core.engine.contracts.specs import OutputFormat, OutputSpec
from injectors_sdk._core.errors import CliContractError, CliParseError, ExecResult

_REGEX_CACHE: dict[str, re.Pattern[str]] = {}


def _get_pattern(pattern: str) -> re.Pattern[str]:
    cached = _REGEX_CACHE.get(pattern)
    if cached is not None:
        return cached
    try:
        compiled = re.compile(pattern)
    except re.error as exc:
        raise CliContractError(f"invalid regex pattern in output spec: {pattern}") from exc
    _REGEX_CACHE[pattern] = compiled
    return compiled


class DefaultOutputParser:
    """Parse command execution output according to an OutputSpec.

    Supports TEXT, JSON, REGEX, LINES, and RAW formats with optional
    Pydantic model validation for JSON and REGEX outputs.
    """

    def parse(
        self,
        result: ExecResult,
        output_spec: OutputSpec,
        model: type[BaseModel] | None = None,
        context: dict[str, object] | None = None,
    ) -> Any:
        """Parse command output according to the output specification.

        Args:
            result: The execution result containing stdout to parse.
            output_spec: Format specification for parsing.
            model: Optional Pydantic model for output validation.
            context: Optional context dict for parser extensions.

        Returns:
            Parsed output (str, dict, list, or Pydantic model instance).

        Raises:
            CliParseError: When output cannot be parsed as expected.
            CliContractError: On invalid format/model combinations.
        """
        stdout = result.stdout
        fmt = output_spec.format

        if fmt in (OutputFormat.TEXT, OutputFormat.RAW):
            if model is not None:
                raise CliContractError(
                    f"output_model is not supported with OutputFormat.{fmt.value.upper()}; "
                    f"use OutputFormat.JSON or OutputFormat.REGEX for model validation"
                )
            return stdout

        if fmt == OutputFormat.LINES:
            if model is not None:
                raise CliContractError(
                    "output_model is not supported with OutputFormat.LINES; "
                    "use OutputFormat.JSON or OutputFormat.REGEX for model validation"
                )
            return stdout.splitlines()

        if fmt == OutputFormat.JSON:
            try:
                parsed = json.loads(stdout)
            except json.JSONDecodeError as exc:
                preview = stdout[:100]
                raise CliParseError(
                    f"stdout is not valid JSON (first 100 chars): {preview!r}"
                ) from exc
            if model is None:
                return parsed
            try:
                return model.model_validate(parsed)
            except ValidationError as exc:
                raise CliParseError("JSON output did not match expected model contract") from exc

        if fmt == OutputFormat.REGEX:
            if output_spec.regex is None:
                raise CliContractError("OutputFormat.REGEX requires OutputSpec.regex")
            match = _get_pattern(output_spec.regex).search(stdout)
            if match is None:
                raise CliParseError(f"regex pattern did not match stdout: {output_spec.regex}")
            parsed = match.groupdict()
            if model is None:
                return parsed
            try:
                return model.model_validate(parsed)
            except ValidationError as exc:
                raise CliParseError("regex output did not match expected model contract") from exc

        raise CliContractError(f"unsupported output format: {fmt}")
