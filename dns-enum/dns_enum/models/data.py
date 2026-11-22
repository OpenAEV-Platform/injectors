import re
from typing import List

from dns_enum.contracts.dns_enum_constants import (
    ASSET_GROUP_ID_KEY,
    BRUTE_FORCE_KEY,
    CLASSIFY_ASSETS_KEY,
    CREATE_ENDPOINTS_KEY,
    DEFAULT_ENDPOINT_TAG,
    DEFAULT_RATE_LIMIT,
    DEFAULT_RECORD_TYPES,
    DEFAULT_TIMEOUT_SECONDS,
    DOMAINS_KEY,
    ENDPOINT_TAG_KEY,
    MAX_RATE_LIMIT,
    MAX_TIMEOUT_SECONDS,
    MAX_WORDLIST_WORDS,
    PASSIVE_SOURCES_KEY,
    RATE_LIMIT_KEY,
    RECORD_TYPES,
    RECORD_TYPES_KEY,
    TIMEOUT_KEY,
    WORDLIST_KEY,
)

# A DNS name: labels of letters, digits and hyphens (no leading or trailing
# hyphen), at least two labels, 253 characters at most. Anything else is refused
# before it reaches a command line.
_LABEL = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
_DOMAIN_RE = re.compile(rf"^(?=.{{1,253}}$){_LABEL}(\.{_LABEL})+$")
_WORD_RE = re.compile(rf"^{_LABEL}(\.{_LABEL})*$")


def _as_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("true", "1", "yes", "on")
    return bool(value)


def _as_bounded_int(value, default: int, maximum: int, name: str) -> int:
    if value is None or (isinstance(value, str) and not value.strip()):
        return default
    try:
        number = int(str(value).strip())
    except ValueError as err:
        raise ValueError(f"{name} must be a whole number, got {value!r}") from err
    if number < 1:
        raise ValueError(f"{name} must be at least 1, got {number}")
    return min(number, maximum)


def parse_domains(raw: str) -> List[str]:
    """Split, normalise and validate the comma-separated root domains, order kept."""
    domains: List[str] = []
    for item in (raw or "").split(","):
        domain = item.strip().lower().rstrip(".")
        if domain.startswith("*."):
            domain = domain[2:]
        if not domain:
            continue
        if not _DOMAIN_RE.match(domain):
            raise ValueError(f"Invalid root domain: {item.strip()!r}")
        if domain not in domains:
            domains.append(domain)
    if not domains:
        raise ValueError("No root domain provided")
    return domains


def parse_record_types(raw) -> List[str]:
    """Return the requested record types in canonical order, defaults when empty."""
    if isinstance(raw, str):
        raw = [item for item in raw.split(",")]
    requested = {str(item).strip().upper() for item in (raw or []) if str(item).strip()}
    unknown = requested - set(RECORD_TYPES)
    if unknown:
        raise ValueError(f"Unsupported record types: {', '.join(sorted(unknown))}")
    if not requested:
        requested = set(DEFAULT_RECORD_TYPES)
    return [record_type for record_type in RECORD_TYPES if record_type in requested]


def parse_wordlist(raw: str) -> List[str]:
    """One label per line (commas accepted), invalid lines dropped, capped in size."""
    words: List[str] = []
    for line in re.split(r"[\n,]", raw or ""):
        word = line.strip().lower().strip(".")
        if word and _WORD_RE.match(word) and word not in words:
            words.append(word)
        if len(words) >= MAX_WORDLIST_WORDS:
            break
    return words


class MessageData:
    def __init__(self, data: dict):
        injection = data["injection"]
        self.inject_id = injection["inject_id"]
        self.contract_id = injection["inject_injector_contract"]["injector_contract_id"]
        content = injection.get("inject_content") or {}

        self.domains = parse_domains(content.get(DOMAINS_KEY, ""))
        self.passive_sources = _as_bool(content.get(PASSIVE_SOURCES_KEY, True))
        self.record_types = parse_record_types(content.get(RECORD_TYPES_KEY))
        self.brute_force = _as_bool(content.get(BRUTE_FORCE_KEY, False))
        self.wordlist = (
            parse_wordlist(content.get(WORDLIST_KEY, "")) if self.brute_force else []
        )
        if self.brute_force and not self.wordlist:
            raise ValueError("Brute force is on but the wordlist is empty")
        self.rate_limit = _as_bounded_int(
            content.get(RATE_LIMIT_KEY),
            DEFAULT_RATE_LIMIT,
            MAX_RATE_LIMIT,
            "Rate limit",
        )
        self.timeout = _as_bounded_int(
            content.get(TIMEOUT_KEY),
            DEFAULT_TIMEOUT_SECONDS,
            MAX_TIMEOUT_SECONDS,
            "Timeout",
        )
        self.create_endpoints = _as_bool(content.get(CREATE_ENDPOINTS_KEY, False))
        self.endpoint_tag = (
            str(content.get(ENDPOINT_TAG_KEY) or "").strip() or DEFAULT_ENDPOINT_TAG
        )
        self.asset_group_id = str(content.get(ASSET_GROUP_ID_KEY) or "").strip() or None
        self.classify_assets = _as_bool(content.get(CLASSIFY_ASSETS_KEY, True))

        self.expectation_types = [
            expectation.get("expectation_type")
            for expectation in content.get("expectations", []) or []
            if expectation.get("expectation_type")
        ]
        self.raw_data = data
