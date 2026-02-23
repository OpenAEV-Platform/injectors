"""Command builder for NetExec CLI invocations."""

import uuid
from typing import Dict, List, Optional

from netexec.contracts.protocol_config import PROTOCOL_CONFIGS, get_option_flag
from netexec.modules_registry import get_module_by_safe_key, safe_module_key

# Options that require writing their output to a file (mandatory argument).
# The command builder auto-generates a temp file path for these.
OPTIONS_REQUIRING_OUTPUT_FILE = {"asreproast", "kerberoasting"}


def build_command(
    protocol: str,
    targets: List[str],
    credentials: Optional[Dict[str, str]] = None,
    options: Optional[List[str]] = None,
    extra_args: Optional[List[str]] = None,
) -> List[str]:
    if not targets:
        raise ValueError(
            f"At least one target is required for {protocol.upper()} command"
        )

    cmd = ["netexec", protocol]
    cmd.extend(targets)

    if credentials:
        if credentials.get("username"):
            cmd.extend(["-u", credentials["username"]])
        if credentials.get("password"):
            cmd.extend(["-p", credentials["password"]])
        if credentials.get("hash"):
            cmd.extend(["-H", credentials["hash"]])
        if credentials.get("domain"):
            cmd.extend(["-d", credentials["domain"]])
        if credentials.get("key_file"):
            cmd.extend(["--key-file", credentials["key_file"]])

    if options:
        if isinstance(options, str):
            cmd.append(options)
        else:
            cmd.extend(options)

    if extra_args:
        cmd.extend(extra_args)

    return cmd


def build_command_version() -> List[str]:
    return ["netexec", "--version"]


# ---------------------------------------------------------------------------
# Credential / port helpers shared by the three extract functions
# ---------------------------------------------------------------------------

def _extract_credentials(content: Dict) -> Optional[Dict[str, str]]:
    credentials: Dict[str, str] = {}
    for key in ("username", "password", "hash", "domain", "key_file"):
        value = content.get(key)
        if value:
            credentials[key] = value
    return credentials or None


def _extract_port_args(content: Dict) -> List[str]:
    port = content.get("port")
    if port:
        return ["--port", str(port)]
    return []


# ---------------------------------------------------------------------------
# Family-specific data extractors
# ---------------------------------------------------------------------------

def extract_data_base(content: Dict, protocol: str) -> Optional[Dict]:
    """Extract form data for a **base protocol** contract (Family 1).

    Handles credentials, port, and protocol-specific extra fields
    (command, ps_command, query, wmi_query).
    """
    data: Dict = {}

    creds = _extract_credentials(content)
    if creds:
        data["credentials"] = creds

    extra_args: List[str] = _extract_port_args(content)

    # Protocol-specific extra fields
    proto_config = PROTOCOL_CONFIGS[protocol]
    for ef in proto_config["base_extra_fields"]:
        value = content.get(ef["key"])
        if value:
            extra_args.extend([ef["flag"], str(value)])

    if extra_args:
        data["extra_args"] = extra_args

    return data or None


def extract_data_option(
    content: Dict, protocol: str, option_id: str
) -> Optional[Dict]:
    """Extract form data for a **protocol + option** contract (Family 2).

    The CLI flag is derived from *option_id* -- it is not in the form content.
    Options in ``OPTIONS_REQUIRING_OUTPUT_FILE`` get an auto-generated temp
    file path appended as argument (e.g. ``--asreproast /tmp/nxc_asreproast_xxxx.txt``).
    """
    data: Dict = {}

    creds = _extract_credentials(content)
    if creds:
        data["credentials"] = creds

    flag = get_option_flag(protocol, option_id)

    if option_id in OPTIONS_REQUIRING_OUTPUT_FILE:
        output_file = f"/tmp/nxc_{option_id}_{uuid.uuid4().hex[:8]}.txt"
        data["options"] = [flag, output_file]
        data["output_file"] = output_file
    else:
        data["options"] = [flag]

    extra_args = _extract_port_args(content)
    if extra_args:
        data["extra_args"] = extra_args

    return data or None


def extract_data_module(
    content: Dict, protocol: str, safe_key: str
) -> Optional[Dict]:
    """Extract form data for a **protocol + module** contract (Family 3).

    The module name is recovered from *safe_key* via the modules registry.
    """
    data: Dict = {}

    creds = _extract_credentials(content)
    if creds:
        data["credentials"] = creds

    extra_args: List[str] = _extract_port_args(content)

    # Resolve module name
    mod = get_module_by_safe_key(protocol, safe_key)
    if mod is None:
        raise ValueError(
            f"Unknown module safe_key '{safe_key}' for protocol '{protocol}'"
        )
    module_name = mod["name"]
    extra_args.extend(["-M", module_name])

    # Per-module option fields (keys: mo_<safe_key>_<OPTION>)
    prefix = f"mo_{safe_key}_"
    module_opts: List[str] = []
    for key, value in content.items():
        if key.startswith(prefix) and value:
            opt_name = key[len(prefix):]
            module_opts.append(f"{opt_name}={value}")

    # Free-text fallback
    module_options_extra = content.get("module_options")
    if module_options_extra:
        module_opts.append(str(module_options_extra))

    if module_opts:
        extra_args.extend(["-o"] + module_opts)

    if extra_args:
        data["extra_args"] = extra_args

    return data or None
