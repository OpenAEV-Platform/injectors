"""Output parser for NetExec command results.

Transforms raw netexec stdout into structured outputs (findings) for OpenAEV.

IMPORTANT: The authentication line ``[+] domain\\user:password (Pwn3d!)`` is
infrastructure -- it is NEVER a finding and must be ignored by all parsers.
Only data produced by modules / options qualifies as finding material.
"""

import re
from typing import Dict, List, Optional, Tuple

from netexec.helpers.credential_extractors import (
    get_account_pw_not_required_extractor,
    get_admin_username_extractor,
    get_asreproastable_extractor,
    get_computer_extractor,
    get_credential_extractor,
    get_delegation_extractor,
    get_group_extractor,
    get_kerberoastable_extractor,
    get_password_policy_extractor,
    get_share_extractor,
    get_sid_extractor,
    get_username_extractor,
    get_vulnerability_extractor,
)


# ---------------------------------------------------------------------------
# Line-level helpers
# ---------------------------------------------------------------------------

# Common netexec line prefix:
#   PROTO/MODULE  IP  PORT  HOSTNAME  <rest>
_LINE_PREFIX = re.compile(
    r"^(?P<label>\S+)\s+"
    r"(?P<ip>\S+)\s+"
    r"(?P<port>\d+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<rest>.*)$"
)

# Authentication confirmation -- must be SKIPPED everywhere.
#   [+] domain\user:secret   or   [+] domain\user:secret (Pwn3d!)
_AUTH_LINE = re.compile(
    r"\[\+\]\s+\S+\\\S+:\S+"
)


def _parse_line(raw: str) -> Tuple[str, str, str, str]:
    """Return (label, ip, hostname, rest) or ("", "", "", "") if unparseable."""
    m = _LINE_PREFIX.match(raw)
    if not m:
        return ("", "", "", raw.strip())
    return (
        m.group("label"),
        m.group("ip"),
        m.group("hostname"),
        m.group("rest").strip(),
    )


def _is_auth_line(rest: str) -> bool:
    return bool(_AUTH_LINE.match(rest))


def _is_banner_line(rest: str) -> bool:
    return rest.startswith("[*]")


def _is_error_line(rest: str) -> bool:
    """Error lines from netexec — already visible in execution traces."""
    return rest.startswith("[-]")


def _is_noise(rest: str) -> bool:
    """Header / separator lines that carry no finding value."""
    if not rest:
        return True
    if rest.startswith("[+] Found following"):
        return True
    if rest.startswith("[+] Dumped"):
        return True
    if rest.startswith("[+] Added"):
        return True
    if rest.startswith("[+] Enumerated"):
        return True
    # Table separators (lines of dashes)
    if re.match(r"^[\s\-]+$", rest):
        return True
    # Table headers (lines with -ColumnName- pattern)
    if re.match(r"^-\w+.*-\s*$", rest):
        return True
    return False


# ---------------------------------------------------------------------------
# Generic dispatch helper
# ---------------------------------------------------------------------------

def _dispatch(getter, finding_lines, ip_to_asset_id_map, family, identifier):
    """Run a per-contract extractor looked up via *getter*, if one exists."""
    if family and identifier:
        extractor = getter(family, identifier)
        if extractor is not None:
            return extractor(finding_lines, ip_to_asset_id_map)
    return []


# ---------------------------------------------------------------------------
# Output field names — must match ContractOutputElement.field
# ---------------------------------------------------------------------------
_DISPATCHERS = [
    ("credentials",                get_credential_extractor),
    ("usernames",                  get_username_extractor),
    ("shares",                     get_share_extractor),
    ("admin_usernames",            get_admin_username_extractor),
    ("groups",                     get_group_extractor),
    ("computers",                  get_computer_extractor),
    ("password_policy",            get_password_policy_extractor),
    ("delegations",                get_delegation_extractor),
    ("sids",                       get_sid_extractor),
    ("vulnerabilities",            get_vulnerability_extractor),
    ("accounts_pw_not_required",   get_account_pw_not_required_extractor),
    ("asreproastable_accounts",    get_asreproastable_extractor),
    ("kerberoastable_accounts",    get_kerberoastable_extractor),
]


# ---------------------------------------------------------------------------
# Public parser
# ---------------------------------------------------------------------------

class NetExecOutputParser:
    """Parses raw netexec stdout into structured findings for OpenAEV."""

    def parse(
        self,
        stdout: str,
        ip_to_asset_id_map: Dict = None,
        family: str = None,
        identifier: str = None,
    ) -> Dict:
        """Parse netexec output and extract structured findings.

        Parameters
        ----------
        stdout : str
            Raw netexec command output.
        ip_to_asset_id_map : dict, optional
            Mapping of IP addresses to OpenAEV asset IDs.
        family : str, optional
            Contract family (``"base"``, ``"option"``, ``"module"``).
        identifier : str, optional
            Contract identifier (option_id or safe_module_key).

        Returns ``{"message": str, "outputs": dict}`` where *outputs* maps
        field names to lists of findings.
        Only populated keys are included; *outputs* may be empty.
        """
        if ip_to_asset_id_map is None:
            ip_to_asset_id_map = {}

        lines = stdout.splitlines()

        # Collect module-output lines (skip auth, banners, errors, noise)
        finding_lines: List[Tuple[str, str, str]] = []  # (ip, hostname, rest)
        for raw in lines:
            label, ip, hostname, rest = _parse_line(raw)
            if not rest:
                continue
            if _is_auth_line(rest):
                continue
            if _is_banner_line(rest):
                continue
            if _is_error_line(rest):
                continue
            if _is_noise(rest):
                continue
            finding_lines.append((ip, hostname, rest))

        # Run all registered dispatchers
        outputs: Dict = {}
        parts: List[str] = []
        for field_name, getter in _DISPATCHERS:
            results = _dispatch(
                getter, finding_lines, ip_to_asset_id_map, family, identifier
            )
            if results:
                outputs[field_name] = results
                parts.append(f"{len(results)} {field_name}")

        message = (
            "NetExec completed: " + ", ".join(parts)
            if parts
            else "NetExec completed: no structured output extracted"
        )

        return {"message": message, "outputs": outputs}
