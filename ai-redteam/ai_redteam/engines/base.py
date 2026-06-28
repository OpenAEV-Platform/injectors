"""Engine abstraction. An engine runs one AI red-team technique against a resolved target and returns
an EngineResult that the injector turns into an execution callback (message + structured outputs).
"""

import base64
import codecs


class EngineResult:
    def __init__(
        self,
        success: bool,
        message: str,
        response: str = "",
        outputs: dict = None,
        status: str = "SUCCESS",
        details: dict = None,
    ):
        self.success = success  # True => attack worked => target vulnerable
        self.message = message
        self.response = response
        self.outputs = outputs or {}
        self.status = status
        self.details = details or {}


class Engine:
    def run(self, content, target, marker, ctx) -> EngineResult:
        raise NotImplementedError


_LEET = str.maketrans({"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"})


def apply_converter(text: str, converter: str) -> str:
    converter = (converter or "none").lower()
    if converter in ("", "none"):
        return text
    if converter == "base64":
        return base64.b64encode(text.encode("utf-8")).decode("ascii")
    if converter == "rot13":
        return codecs.encode(text, "rot_13")
    if converter == "leetspeak":
        return text.translate(_LEET)
    if converter == "unicode_escape":
        return text.encode("unicode_escape").decode("ascii")
    if converter == "reverse":
        return text[::-1]
    return text
