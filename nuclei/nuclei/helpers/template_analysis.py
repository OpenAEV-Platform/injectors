"""Read what a Nuclei template needs and does before it runs.

A CVE template can depend on values only the operator knows (``{{username}}`` and
``{{password}}`` of an authenticated check, any other unresolved ``{{name}}``). Run
without them, Nuclei sends the requests with empty values and the template can never
match: the result reads "not vulnerable" while nothing was tested. A template can
also change state on the target (an exploit POST, an RCE probe).

``analyze_template`` reads a template file once and returns:

- the variables it needs from the operator (the ``-var`` inputs of the contract),
- whether it is authenticated, intrusive or read-only,
- the prerequisites its description states.

The contract generator exposes them as contract inputs and metadata, and the
execution path refuses to run a template whose required variables are missing.
"""

import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

import yaml

# Values Nuclei fills itself from the target or its runtime: never an operator input.
# https://docs.projectdiscovery.io/templates/reference/variables
_BUILTIN_VARIABLES = {
    "baseurl",
    "rooturl",
    "hostname",
    "host",
    "port",
    "path",
    "file",
    "scheme",
    "input",
    "fqdn",
    "rdn",
    "dn",
    "tld",
    "sd",
    "ip",
    "interactsh-url",
    "interactsh_url",
    "interactsh-server",
    "randstr",
    "template-id",
    "template-path",
    "template-dir",
    "timestamp",
    "unix_time",
    "user-agent",
}
# Response parts a later request of a flow can reference (body_1, header_2...).
_RESPONSE_PART = re.compile(
    r"^(body|header|all_headers|status_code|content_length|response|request|raw|"
    r"content_type|duration|cookie|redirect|location|matched|host|data)(_\d+)?$",
    re.IGNORECASE,
)
_RANDSTR = re.compile(r"^randstr(_\w+)?$", re.IGNORECASE)
_PLACEHOLDER = re.compile(r"\{\{\s*([^{}]+?)\s*\}\}")
_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*$")

# Request parts that carry what is sent to the target. Matchers and extractors read
# responses: their placeholders are never inputs.
_REQUEST_KEYS = ("raw", "path", "body", "headers", "payload", "data", "code", "args")
_SKIPPED_KEYS = ("matchers", "extractors", "matchers-condition")
_PROTOCOLS = (
    "http",
    "requests",
    "network",
    "tcp",
    "dns",
    "ssl",
    "websocket",
    "headless",
    "file",
    "whois",
    "code",
    "javascript",
)

_STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_INTRUSIVE_TAGS = {"rce", "intrusive", "dos", "fuzz", "fuzzing"}
_INTRUSIVE_PROTOCOLS = {"code", "javascript"}
_RAW_METHOD = re.compile(r"^\s*([A-Z]+)\s+\S+\s+HTTP/", re.MULTILINE)

# The sentences of a description that state a condition the target must meet.
_PREREQUISITE_HINT = re.compile(
    r"\b(must|requires?|required|only (?:when|if)|prerequisite|by default|"
    r"authenticated|credentials?|with (?:the )?\w+ or higher)\b",
    re.IGNORECASE,
)
_MAX_PREREQUISITES = 5
_MAX_PREREQUISITE_LENGTH = 300

CREDENTIAL_VARIABLES = ("username", "password")
SECRET_VARIABLES = {
    "password",
    "pass",
    "passwd",
    "token",
    "api_key",
    "apikey",
    "secret",
}


@dataclass
class TemplateAnalysis:
    """What a template needs and does, read from its YAML."""

    variables: List[str] = field(default_factory=list)
    authenticated: bool = False
    intrusive: bool = False
    tags: List[str] = field(default_factory=list)
    prerequisites: List[str] = field(default_factory=list)

    @property
    def read_only(self) -> bool:
        return not self.intrusive

    @property
    def needs_credentials(self) -> bool:
        return any(name in self.variables for name in CREDENTIAL_VARIABLES)

    def to_metadata(self) -> Dict[str, Any]:
        """The machine-readable flags stored in the contract content."""
        return {
            "authenticated": self.authenticated,
            "intrusive": self.intrusive,
            "read_only": self.read_only,
            "required_variables": list(self.variables),
            "prerequisites": list(self.prerequisites),
        }


def is_secret_variable(name: str) -> bool:
    return name.lower() in SECRET_VARIABLES


def templates_directory() -> str:
    """Where Nuclei keeps its templates: NUCLEI_TEMPLATES_DIR, else its default
    ~/nuclei-templates."""
    return os.environ.get("NUCLEI_TEMPLATES_DIR") or os.path.join(
        os.path.expanduser("~"), "nuclei-templates"
    )


def resolve_template_path(template: Optional[str]) -> Optional[str]:
    """The file a contract's template path points to, or None when it is not a
    single readable template file (a directory, a tag scan, a missing file)."""
    if not template or not isinstance(template, str):
        return None
    candidate = (
        template
        if os.path.isabs(template)
        else os.path.join(templates_directory(), template)
    )
    if not candidate.endswith((".yaml", ".yml")) or not os.path.isfile(candidate):
        return None
    return candidate


def analyze_template_file(path: Optional[str]) -> Optional[TemplateAnalysis]:
    """Analyse a template file; None when it cannot be read or parsed."""
    if not path:
        return None
    try:
        with open(path, encoding="utf-8") as handle:
            document = yaml.safe_load(handle)
    except (OSError, yaml.YAMLError, UnicodeDecodeError):
        return None
    if not isinstance(document, dict):
        return None
    return analyze_template(document)


def analyze_template(document: Dict[str, Any]) -> TemplateAnalysis:
    info = document.get("info") or {}
    tags = _tags(info.get("tags"))
    defined = _defined_names(document)

    placeholders: List[str] = []
    for protocol in _PROTOCOLS:
        for request in _as_list(document.get(protocol)):
            for value in _request_values(request):
                placeholders.extend(_PLACEHOLDER.findall(value))

    variables: List[str] = []
    for placeholder in placeholders:
        name = placeholder.strip()
        if not _IDENTIFIER.match(name) or name in variables:
            continue
        lowered = name.lower()
        if (
            lowered in _BUILTIN_VARIABLES
            or _RESPONSE_PART.match(name)
            or _RANDSTR.match(name)
            or name in defined
        ):
            continue
        variables.append(name)

    authenticated = "authenticated" in tags or any(
        name in variables for name in CREDENTIAL_VARIABLES
    )
    if "authenticated" in tags and not variables:
        # Tagged authenticated but no visible placeholder (a login hidden in a
        # helper): it still cannot match without credentials.
        variables.extend(CREDENTIAL_VARIABLES)

    return TemplateAnalysis(
        variables=variables,
        authenticated=authenticated,
        intrusive=_is_intrusive(document, tags),
        tags=sorted(tags),
        prerequisites=_prerequisites(info.get("description")),
    )


def _tags(raw: Any) -> Set[str]:
    if isinstance(raw, str):
        return {tag.strip().lower() for tag in raw.split(",") if tag.strip()}
    if isinstance(raw, list):
        return {str(tag).strip().lower() for tag in raw if str(tag).strip()}
    return set()


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _defined_names(document: Dict[str, Any]) -> Set[str]:
    """Names the template defines itself: variables, payloads, extractor names."""
    names: Set[str] = set()
    variables = document.get("variables")
    if isinstance(variables, dict):
        names.update(str(key) for key in variables)
    for protocol in _PROTOCOLS:
        for request in _as_list(document.get(protocol)):
            if not isinstance(request, dict):
                continue
            for key in ("payloads", "variables"):
                block = request.get(key)
                if isinstance(block, dict):
                    names.update(str(name) for name in block)
            for extractor in _as_list(request.get("extractors")):
                if isinstance(extractor, dict) and extractor.get("name"):
                    names.add(str(extractor["name"]))
    return names


def _request_values(request: Any) -> List[str]:
    """Every string a request sends, matchers and extractors left out."""
    values: List[str] = []
    if isinstance(request, str):
        return [request]
    if not isinstance(request, dict):
        return values
    for key, value in request.items():
        if key in _SKIPPED_KEYS:
            continue
        if key in _REQUEST_KEYS or isinstance(value, (list, dict)):
            values.extend(_strings(value))
    return values


def _strings(value: Any) -> List[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [text for item in value for text in _strings(item)]
    if isinstance(value, dict):
        return [
            text
            for key, item in value.items()
            if key not in _SKIPPED_KEYS
            for text in _strings(item)
        ]
    return []


def _is_intrusive(document: Dict[str, Any], tags: Set[str]) -> bool:
    if tags & _INTRUSIVE_TAGS:
        return True
    if any(document.get(protocol) for protocol in _INTRUSIVE_PROTOCOLS):
        return True
    for request in _as_list(document.get("http")) + _as_list(document.get("requests")):
        if not isinstance(request, dict):
            continue
        if request.get("fuzzing"):
            return True
        method = str(request.get("method") or "").upper()
        if method in _STATE_CHANGING_METHODS:
            return True
        for raw in _as_list(request.get("raw")):
            if isinstance(raw, str) and any(
                found in _STATE_CHANGING_METHODS for found in _RAW_METHOD.findall(raw)
            ):
                return True
    return False


def _prerequisites(description: Any) -> List[str]:
    if not isinstance(description, str):
        return []
    sentences = re.split(r"(?<=[.!?])\s+", " ".join(description.split()))
    found = [
        sentence[:_MAX_PREREQUISITE_LENGTH]
        for sentence in sentences
        if sentence and _PREREQUISITE_HINT.search(sentence)
    ]
    return found[:_MAX_PREREQUISITES]
