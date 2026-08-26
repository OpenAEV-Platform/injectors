"""Output parsing adapters."""

import json
import re
from typing import Any

from ..contracts import ExecutionSpecification
from ..errors import ParsingError


class OutputParserAdapter:
    """Parse exact stdout according to the immutable specification."""

    def parse(
        self, specification: ExecutionSpecification, payload: bytes
    ) -> Any | ParsingError:
        """Return parsed output or safe parser context without process evidence."""
        parser = specification.output.parser.lower()
        if parser == "raw":
            return payload
        try:
            text = payload.decode("utf-8")
            if parser == "text":
                return text
            if parser == "json":
                return json.loads(text)
            if parser == "lines":
                return text.splitlines()
            if parser == "regex":
                if specification.output.pattern is None:
                    raise ValueError("regex parser requires a pattern")
                match = re.search(specification.output.pattern, text)
                if match is None:
                    raise ValueError("output did not match the regular expression")
                if match.groupdict():
                    return match.groupdict()
                if len(match.groups()) == 1:
                    return match.group(1)
                return match.groups() or match.group(0)
            raise ValueError(
                f"unsupported output parser: {specification.output.parser}"
            )
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            re.error,
            ValueError,
        ) as error:
            return ParsingError(
                "unable to parse process output",
                context=(("parser", specification.output.parser),),
                cause=f"{type(error).__name__}: {error}",
            )
