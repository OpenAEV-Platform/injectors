"""Registry mapping each contract to its output parser types.

Each option/module is mapped to a set of output types it can produce.
This drives both:
  - which ``ContractOutputElement`` are declared on each contract
  - which extractors the parser runs after execution

To add a new mapping, simply add the identifier to the appropriate set below.
Contracts not listed here default to ``{"action_output"}`` (the raw stdout,
stored with isFindingCompatible=False so it never shows up in the Findings
tab, but stays available as a chaining/event filter).
Contracts in ``_NO_OUTPUT`` produce no structured findings at all.
"""

# ---------------------------------------------------------------------------
# Output type constants
# ---------------------------------------------------------------------------
ACTION_OUTPUT = "action_output"
CREDENTIALS = "credentials"
USERNAME = "username"
SHARE = "share"
FILE = "file"
ADMIN_USERNAME = "admin_username"
GROUP = "group"
COMPUTER = "computer"
PASSWORD_POLICY = "password_policy"
DELEGATION = "delegation"
SID = "sid"
VULNERABILITY = "vulnerability"
ACCOUNT_PW_NOT_REQUIRED = "account_with_password_not_required"
ASREPROASTABLE = "asreproastable_account"
KERBEROASTABLE = "kerberoastable_account"
EXPECTATION_SIGNATURE = "expectation_signatures"

# ---------------------------------------------------------------------------
# Options that produce NO structured output (actions, config toggles)
# ---------------------------------------------------------------------------
_NO_OUTPUT_OPTIONS = {
    "local_auth",  # just a flag, no extra output
    "no_output",  # explicitly no output
    "screenshot",  # binary file, not parseable text
    "nla_screenshot",  # binary file
    "sudo_check",  # pass/fail only
    "bloodhound",  # produces JSON files, not stdout
}

# ---------------------------------------------------------------------------
# Options → output types
# ---------------------------------------------------------------------------
_OPTION_OUTPUTS = {
    # Credential dumps
    "sam": {CREDENTIALS, ACTION_OUTPUT},
    "lsa": {CREDENTIALS, ACTION_OUTPUT},
    "ntds": {CREDENTIALS, ACTION_OUTPUT},
    "gmsa": {CREDENTIALS, ACTION_OUTPUT},
    "asreproast": {ASREPROASTABLE, ACTION_OUTPUT},
    "kerberoasting": {KERBEROASTABLE, ACTION_OUTPUT},
    # Enumeration (text + possible credential leaks in descriptions)
    "users": {ACTION_OUTPUT, CREDENTIALS, USERNAME},
    "groups": {ACTION_OUTPUT, GROUP},
    "local_groups": {ACTION_OUTPUT, GROUP},
    "loggedon_users": {ACTION_OUTPUT, USERNAME},
    "computers": {ACTION_OUTPUT, COMPUTER},
    "rid_brute": {ACTION_OUTPUT, USERNAME},
    "active_users": {ACTION_OUTPUT, CREDENTIALS, USERNAME},
    "trusted_for_delegation": {ACTION_OUTPUT, DELEGATION},
    "find_delegation": {ACTION_OUTPUT, DELEGATION},
    "password_not_required": {ACTION_OUTPUT, ACCOUNT_PW_NOT_REQUIRED},
    "admin_count": {ACTION_OUTPUT, ADMIN_USERNAME},
    "dc_list": {ACTION_OUTPUT},
    "get_sid": {ACTION_OUTPUT, SID},
    # Shares / disks / files
    "shares": {ACTION_OUTPUT, SHARE},
    "enum_shares": {ACTION_OUTPUT},
    "disks": {ACTION_OUTPUT},
    "interfaces": {ACTION_OUTPUT},
    "ls": {ACTION_OUTPUT},
    # Password policy
    "pass_pol": {ACTION_OUTPUT, PASSWORD_POLICY},
}

# ---------------------------------------------------------------------------
# Modules → output types
# ---------------------------------------------------------------------------
_MODULE_OUTPUTS = {
    # Credential-dumping modules
    "lsassy": {CREDENTIALS, ACTION_OUTPUT},
    "handlekatz": {CREDENTIALS, ACTION_OUTPUT},
    "procdump": {CREDENTIALS, ACTION_OUTPUT},
    "nanodump": {CREDENTIALS, ACTION_OUTPUT},
    "hash_spider": {CREDENTIALS, ACTION_OUTPUT},
    "dpapi_hash": {CREDENTIALS, ACTION_OUTPUT},
    "gpp_password": {CREDENTIALS, ACTION_OUTPUT},
    "gpp_autologin": {CREDENTIALS, ACTION_OUTPUT},
    "masky": {CREDENTIALS, ACTION_OUTPUT},
    "ntdsutil": {CREDENTIALS, ACTION_OUTPUT},
    "msol": {CREDENTIALS, ACTION_OUTPUT},
    "wam": {CREDENTIALS, ACTION_OUTPUT},
    "wifi": {CREDENTIALS, ACTION_OUTPUT},
    "winscp": {CREDENTIALS, ACTION_OUTPUT},
    "mremoteng": {CREDENTIALS, ACTION_OUTPUT},
    "mobaxterm": {CREDENTIALS, ACTION_OUTPUT},
    "rdcman": {CREDENTIALS, ACTION_OUTPUT},
    "firefox": {CREDENTIALS, ACTION_OUTPUT},
    "iis": {CREDENTIALS, ACTION_OUTPUT},
    "keepass_discover": {CREDENTIALS, ACTION_OUTPUT},
    "keepass_trigger": {CREDENTIALS, ACTION_OUTPUT},
    "veeam": {CREDENTIALS, ACTION_OUTPUT},
    "vnc": {CREDENTIALS, ACTION_OUTPUT},
    "putty": {CREDENTIALS, ACTION_OUTPUT},
    "teams_localdb": {CREDENTIALS, ACTION_OUTPUT},
    "notepadplusplus": {CREDENTIALS, ACTION_OUTPUT},
    "snipped": {CREDENTIALS, ACTION_OUTPUT},
    "powershell_history": {CREDENTIALS, ACTION_OUTPUT},
    "reg_winlogon": {CREDENTIALS, ACTION_OUTPUT},
    "security_questions": {CREDENTIALS, ACTION_OUTPUT},
    "backup_operator": {CREDENTIALS, ACTION_OUTPUT},
    # User / group / AD enumeration
    "get_desc_users": {ACTION_OUTPUT, CREDENTIALS},
    "user_desc": {ACTION_OUTPUT, CREDENTIALS},
    "find_computer": {ACTION_OUTPUT},
    "groupmembership": {ACTION_OUTPUT},
    "group_mem": {ACTION_OUTPUT},
    "whoami": {ACTION_OUTPUT},
    "pre2k": {ACTION_OUTPUT, CREDENTIALS},
    "obsolete": {ACTION_OUTPUT},
    "enum_logins": {ACTION_OUTPUT},
    "pso": {ACTION_OUTPUT},
    "maq": {ACTION_OUTPUT},
    # Vulnerability / exploit detection. Modules that print an explicit
    # "VULNERABLE" verdict emit a VULNERABILITY finding (shared verdict
    # extractor). webdav / ntlmv1 / timeroast stay action_output-only: their
    # positive output is not a VULNERABLE verdict, so it needs dedicated
    # parsing (TODO).
    "ms17_010": {ACTION_OUTPUT, VULNERABILITY},
    "smbghost": {ACTION_OUTPUT, VULNERABILITY},
    "zerologon": {ACTION_OUTPUT, VULNERABILITY},
    "nopac": {ACTION_OUTPUT, VULNERABILITY},
    "printnightmare": {ACTION_OUTPUT, VULNERABILITY},
    "petitpotam": {ACTION_OUTPUT, VULNERABILITY},
    "shadowcoerce": {ACTION_OUTPUT, VULNERABILITY},
    "dfscoerce": {ACTION_OUTPUT, VULNERABILITY},
    "coerce_plus": {ACTION_OUTPUT, VULNERABILITY},
    "printerbug": {ACTION_OUTPUT, VULNERABILITY},
    "spooler": {ACTION_OUTPUT, VULNERABILITY},
    "webdav": {ACTION_OUTPUT},
    "ntlmv1": {ACTION_OUTPUT},
    "ldap_checker": {ACTION_OUTPUT, VULNERABILITY},
    "timeroast": {ACTION_OUTPUT},
    # Network / infra enumeration
    "get_network": {ACTION_OUTPUT},
    "subnets": {ACTION_OUTPUT},
    "enum_dns": {ACTION_OUTPUT},
    "ioxidresolver": {ACTION_OUTPUT},
    "get_netconnections": {ACTION_OUTPUT},
    "bitlocker": {ACTION_OUTPUT},
    "enum_ca": {ACTION_OUTPUT},
    "enum_av": {ACTION_OUTPUT},
    "adcs": {ACTION_OUTPUT},
    "sccm": {ACTION_OUTPUT},
    "hyperv_host": {ACTION_OUTPUT},
    "uac": {ACTION_OUTPUT},
    "wcc": {ACTION_OUTPUT},
    "recent_files": {ACTION_OUTPUT},
    # File spider: stdout only carries stats; the per-file list is written to a
    # JSON metadata file, parsed separately into `file` findings.
    "spider_plus": {ACTION_OUTPUT, FILE},
    # Actions (execute something, limited stdout findings)
    "add_computer": {ACTION_OUTPUT},
    "empire_exec": {ACTION_OUTPUT},
    "met_inject": {ACTION_OUTPUT},
    "web_delivery": {ACTION_OUTPUT},
    "schtask_as": {ACTION_OUTPUT},
    "drop_sc": {ACTION_OUTPUT},
    "scuffy": {ACTION_OUTPUT},
    "slinky": {ACTION_OUTPUT},
    "impersonate": {ACTION_OUTPUT},
    "pi": {ACTION_OUTPUT},
    "install_elevated": {ACTION_OUTPUT},
    "remove_mic": {ACTION_OUTPUT},
    "rdp": {ACTION_OUTPUT},
    "shadowrdp": {ACTION_OUTPUT},
    "wdigest": {ACTION_OUTPUT},
    "runasppl": {ACTION_OUTPUT},
    "remote_uac": {ACTION_OUTPUT},
    "reg_query": {ACTION_OUTPUT},
    "daclread": {ACTION_OUTPUT},
    "mssql_priv": {ACTION_OUTPUT},
    "enum_impersonate": {ACTION_OUTPUT},
    "enum_links": {ACTION_OUTPUT},
    "exec_on_link": {ACTION_OUTPUT},
    "link_xpcmd": {ACTION_OUTPUT},
    "link_enable_cmdshell": {ACTION_OUTPUT},
    "mssql_coerce": {ACTION_OUTPUT},
    "test_connection": {ACTION_OUTPUT},
    "badsuccessor": {ACTION_OUTPUT},
    "raisechild": {ACTION_OUTPUT},
    "notepad": {ACTION_OUTPUT},
    "recyclebin": {ACTION_OUTPUT},
    "enable_cmdshell": {ACTION_OUTPUT},
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get_option_output_types(option_id: str) -> set[str]:
    """Return the set of output types for a given option contract."""
    if option_id in _NO_OUTPUT_OPTIONS:
        return set()
    return _OPTION_OUTPUTS.get(option_id, {ACTION_OUTPUT})


def get_module_output_types(safe_module_key: str) -> set[str]:
    """Return the set of output types for a given module contract."""
    return _MODULE_OUTPUTS.get(safe_module_key, {ACTION_OUTPUT})


def get_base_output_types() -> set[str]:
    """Base protocol contracts always produce the raw stdout as action_output."""
    return {ACTION_OUTPUT}
