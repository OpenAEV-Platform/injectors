"""Centralised protocol configuration for all NetExec contracts."""

from typing import Dict, List


def _opt(option_id: str, flag: str, label: str) -> Dict:
    return {"id": option_id, "flag": flag, "label": label}


def _extra(key: str, label: str, flag: str) -> Dict:
    return {"key": key, "label": label, "flag": flag}


PROTOCOL_CONFIGS: Dict[str, Dict] = {
    "smb": {
        "default_port": "445",
        "credentials": ["username", "password", "hash", "domain"],
        "base_extra_fields": [
            _extra("command", "Command to execute (-x)", "-x"),
            _extra("ps_command", "PowerShell command (-X)", "-X"),
        ],
        "options": [
            _opt("shares", "--shares", "Share Listing"),
            _opt("pass_pol", "--pass-pol", "Password Policy"),
            _opt("users", "--users", "User Listing"),
            _opt("groups", "--groups", "Group Listing"),
            _opt("local_groups", "--local-groups", "Local Group Listing"),
            _opt("loggedon_users", "--loggedon-users", "Logged-on Users"),
            _opt("computers", "--computers", "Computer Listing"),
            _opt("rid_brute", "--rid-brute", "RID Brute Force"),
            _opt("disks", "--disks", "Disk Listing"),
            _opt("interfaces", "--interfaces", "Interface Listing"),
            _opt("local_auth", "--local-auth", "Local Authentication"),
            _opt("sam", "--sam", "SAM Dump"),
            _opt("lsa", "--lsa", "LSA Dump"),
            _opt("ntds", "--ntds", "NTDS Dump"),
        ],
    },
    "ssh": {
        "default_port": "22",
        "credentials": ["username", "password", "key_file"],
        "base_extra_fields": [
            _extra("command", "Command to execute (-x)", "-x"),
        ],
        "options": [
            _opt("sudo_check", "--sudo-check", "Sudo Check"),
            _opt("no_output", "--no-output", "No Output"),
        ],
    },
    "ldap": {
        "default_port": "389",
        "credentials": ["username", "password", "hash", "domain"],
        "base_extra_fields": [],
        "options": [
            _opt("users", "--users", "User Listing"),
            _opt("groups", "--groups", "Group Listing"),
            _opt("computers", "--computers", "Computer Listing"),
            _opt("dc_list", "--dc-list", "DC Listing"),
            _opt("get_sid", "--get-sid", "Get SID"),
            _opt("active_users", "--active-users", "Active Users"),
            _opt("trusted_for_delegation", "--trusted-for-delegation", "Trusted for Delegation"),
            _opt("find_delegation", "--find-delegation", "Find Delegation"),
            _opt("password_not_required", "--password-not-required", "Password Not Required"),
            _opt("admin_count", "--admin-count", "Admin Count"),
            _opt("gmsa", "--gmsa", "gMSA Passwords"),
            _opt("asreproast", "--asreproast", "AS-REP Roasting"),
            _opt("kerberoasting", "--kerberoasting", "Kerberoasting"),
            _opt("bloodhound", "--bloodhound", "BloodHound Collection"),
        ],
    },
    "winrm": {
        "default_port": "5985",
        "credentials": ["username", "password", "hash", "domain"],
        "base_extra_fields": [
            _extra("command", "Command to execute (-x)", "-x"),
            _extra("ps_command", "PowerShell command (-X)", "-X"),
        ],
        "options": [
            _opt("local_auth", "--local-auth", "Local Authentication"),
            _opt("sam", "--sam", "SAM Dump"),
            _opt("lsa", "--lsa", "LSA Dump"),
            _opt("no_output", "--no-output", "No Output"),
        ],
    },
    "mssql": {
        "default_port": "1433",
        "credentials": ["username", "password", "hash", "domain"],
        "base_extra_fields": [
            _extra("query", "SQL query (-q)", "-q"),
            _extra("command", "OS command to execute (-x)", "-x"),
            _extra("ps_command", "PowerShell command (-X)", "-X"),
        ],
        "options": [
            _opt("local_auth", "--local-auth", "Local Authentication"),
            _opt("rid_brute", "--rid-brute", "RID Brute Force"),
            _opt("no_output", "--no-output", "No Output"),
        ],
    },
    "rdp": {
        "default_port": "3389",
        "credentials": ["username", "password", "hash", "domain"],
        "base_extra_fields": [
            _extra("command", "Command to execute (-x)", "-x"),
            _extra("ps_command", "PowerShell command (-X)", "-X"),
        ],
        "options": [
            _opt("local_auth", "--local-auth", "Local Authentication"),
            _opt("screenshot", "--screenshot", "Screenshot"),
            _opt("nla_screenshot", "--nla-screenshot", "NLA Screenshot"),
        ],
    },
    "vnc": {
        "default_port": "5900",
        "credentials": ["password"],
        "base_extra_fields": [],
        "options": [
            _opt("screenshot", "--screenshot", "Screenshot"),
        ],
    },
    "ftp": {
        "default_port": "21",
        "credentials": ["username", "password"],
        "base_extra_fields": [],
        "options": [
            _opt("ls", "--ls", "File Listing"),
        ],
    },
    "wmi": {
        "default_port": "135",
        "credentials": ["username", "password", "hash", "domain"],
        "base_extra_fields": [
            _extra("command", "Command to execute (-x)", "-x"),
            _extra("ps_command", "PowerShell command (-X)", "-X"),
            _extra("wmi_query", "WMI query (--wmi-query)", "--wmi-query"),
        ],
        "options": [
            _opt("local_auth", "--local-auth", "Local Authentication"),
            _opt("no_output", "--no-output", "No Output"),
        ],
    },
    "nfs": {
        "default_port": "111",
        "credentials": [],
        "base_extra_fields": [],
        "options": [
            _opt("shares", "--shares", "Share Listing"),
            _opt("enum_shares", "--enum-shares", "Enumerate Shares"),
            _opt("ls", "--ls", "File Listing"),
        ],
    },
}

SUPPORTED_PROTOCOLS: List[str] = list(PROTOCOL_CONFIGS.keys())


def get_option_flag(protocol: str, option_id: str) -> str:
    """Look up the CLI flag for a given protocol option ID."""
    config = PROTOCOL_CONFIGS.get(protocol)
    if config is None:
        raise ValueError(f"Unknown protocol: '{protocol}'")
    for opt in config["options"]:
        if opt["id"] == option_id:
            return opt["flag"]
    raise ValueError(f"Unknown option '{option_id}' for protocol '{protocol}'")


def build_command_template(
    protocol: str,
    flag: str = None,
    module: str = None,
) -> str:
    """Build a human-readable command template for contract descriptions."""
    config = PROTOCOL_CONFIGS[protocol]
    parts = [f"nxc {protocol} #{{TARGET}}"]

    creds = config["credentials"]
    if "username" in creds:
        parts.append("-u #{USERNAME}")
    if "password" in creds:
        parts.append("-p #{PASSWORD}")

    if flag:
        parts.append(flag)

    if module:
        parts.append(f"-M {module}")

    return " ".join(parts)
