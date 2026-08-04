"""Registry mapping each NetExec contract to its MITRE ATT&CK technique id(s).

Mirrors the shape of ``output_registry.py``: base protocol contracts are keyed
by protocol name, option contracts by option id (shared across protocols --
the same option id always maps to the same technique regardless of which
protocol carries it), and module contracts by ``safe_module_key``.

Contracts not listed here get no attack pattern (empty list) -- either because
the action has no adversary-relevant technique (e.g. ``no_output``,
``test_connection``) or because the option/module wasn't confidently mappable.
See docs/specs/2026-08-ttp-mapping-netexec.md for the research and rationale
behind every mapping below.
"""

# ---------------------------------------------------------------------------
# Base protocol contracts -- one contract per protocol, covering base auth
# plus whichever of command/ps_command/query/wmi_query that protocol exposes.
# Mapped as the union of techniques its optional fields can trigger.
# ---------------------------------------------------------------------------
_BASE_ATTACK_PATTERNS: dict[str, list[str]] = {
    "smb": ["T1059.003", "T1059.001", "T1110.001", "T1550.002"],
    "ssh": ["T1059.004", "T1110.001"],
    "ldap": ["T1110.001"],
    "winrm": ["T1059.003", "T1059.001", "T1021.006"],
    "mssql": ["T1059", "T1059.003", "T1059.001", "T1110.001"],
    "rdp": ["T1059.003", "T1059.001", "T1021.001"],
    "vnc": ["T1021.005"],
    "ftp": ["T1110.001"],
    "wmi": ["T1047", "T1059.001"],
    "nfs": [],  # unauthenticated mounts are common; not a credential-guessing action
}

# ---------------------------------------------------------------------------
# Option contracts -- keyed by option id, shared across every protocol that
# exposes it (e.g. "shares" means the same thing on smb and nfs).
# ---------------------------------------------------------------------------
_OPTION_ATTACK_PATTERNS: dict[str, list[str]] = {
    "shares": ["T1135"],
    "enum_shares": ["T1135"],
    "ls": ["T1083"],
    "pass_pol": ["T1201"],
    "users": ["T1087.002"],
    "groups": ["T1069.002"],
    "local_groups": ["T1069.001"],
    "loggedon_users": ["T1033"],
    "computers": ["T1018"],
    "rid_brute": ["T1087.001"],
    "disks": ["T1680"],
    "interfaces": ["T1016"],
    "local_auth": ["T1078.003"],
    "sam": ["T1003.002"],
    "lsa": ["T1003.004"],
    "ntds": ["T1003.003"],
    "sudo_check": ["T1548.003"],
    "no_output": [],  # pure output-suppression flag
    "dc_list": ["T1018"],
    "get_sid": ["T1087.002"],
    "active_users": ["T1087.002"],
    "trusted_for_delegation": ["T1558"],
    "find_delegation": ["T1558"],
    "password_not_required": ["T1087.002"],
    "admin_count": ["T1087.002"],
    "gmsa": ["T1003"],
    "asreproast": ["T1558.004"],
    "kerberoasting": ["T1558.003"],
    "bloodhound": ["T1482"],
    "screenshot": ["T1113"],
    "nla_screenshot": ["T1113"],
}

# ---------------------------------------------------------------------------
# Module contracts -- keyed by safe_module_key(module["name"]).
# ---------------------------------------------------------------------------
_MODULE_ATTACK_PATTERNS: dict[str, list[str]] = {
    "add_computer": ["T1136.002"],
    "adcs": ["T1087.002"],
    "backup_operator": ["T1003.002"],
    "bitlocker": ["T1555"],
    "coerce_plus": ["T1187"],
    "daclread": ["T1087.002"],
    "dfscoerce": ["T1187"],
    "dpapi_hash": ["T1555"],
    "drop_sc": ["T1187"],
    "empire_exec": ["T1059.001"],
    "enum_av": ["T1518.001"],
    "enum_ca": ["T1087.002"],
    "enum_dns": ["T1016"],
    "enum_impersonate": ["T1087"],
    "enum_links": ["T1018"],
    "enum_logins": ["T1087"],
    "enum_trusts": ["T1482"],
    "exec_on_link": ["T1059.003"],
    "find_computer": ["T1018"],
    "firefox": ["T1555.003"],
    "get_desc_users": ["T1087.002"],
    "get_network": ["T1016"],
    "get_unixUserPassword": ["T1552.001"],
    "get_userPassword": ["T1552.001"],
    "get_netconnections": ["T1049"],
    "gpp_autologin": ["T1552.006"],
    "gpp_password": ["T1552.006"],
    "group_mem": ["T1069.002"],
    "groupmembership": ["T1069.002"],
    "handlekatz": ["T1003.001"],
    "hash_spider": ["T1003"],
    "hyperv_host": ["T1082"],
    "iis": ["T1552.001"],
    "impersonate": ["T1134.001"],
    "install_elevated": ["T1548.002"],
    "ioxidresolver": ["T1018"],
    "keepass_discover": ["T1555.005"],
    "keepass_trigger": ["T1555.005"],
    "laps": ["T1552.001"],
    "ldap_checker": ["T1046"],
    "link_xpcmd": ["T1059.003"],
    "lsassy": ["T1003.001"],
    "maq": ["T1087.002"],
    "masky": ["T1649"],
    "met_inject": ["T1055"],
    "mobaxterm": ["T1552.001"],
    "mremoteng": ["T1552.001"],
    "ms17_010": ["T1210"],
    "msol": ["T1552.001"],
    "mssql_coerce": ["T1187"],
    "mssql_priv": ["T1068"],
    "nanodump": ["T1003.001"],
    "nopac": ["T1068"],
    "notepadplusplus": ["T1552.001"],
    "ntdsutil": ["T1003.003"],
    "ntlmv1": ["T1046"],
    "obsolete": ["T1082"],
    "petitpotam": ["T1187"],
    "pi": ["T1055"],
    "powershell_history": ["T1552.001"],
    "pre2k": ["T1087.002"],
    "printerbug": ["T1187"],
    "printnightmare": ["T1210"],
    "procdump": ["T1003.001"],
    "pso": ["T1201"],
    "putty": ["T1552.002"],
    "rdcman": ["T1552.001"],
    "rdp": ["T1112"],
    "recent_files": ["T1083"],
    "reg_query": ["T1012"],
    "reg_winlogon": ["T1552.002"],
    "remote_uac": ["T1548.002"],
    "remove_mic": ["T1222.001"],
    "runasppl": ["T1112"],
    "sccm": ["T1518"],
    "schtask_as": ["T1053.002"],
    "scuffy": ["T1187"],
    "security_questions": ["T1552.002"],
    "shadowcoerce": ["T1187"],
    "shadowrdp": ["T1563.002"],
    "slinky": ["T1187"],
    "smbghost": ["T1210"],
    "snipped": ["T1552.001"],
    "spider_plus": ["T1083", "T1005"],
    "spooler": ["T1046"],
    "subnets": ["T1016"],
    "teams_localdb": ["T1528"],
    "test_connection": [],  # operational check, not adversary-relevant
    "timeroast": ["T1558"],
    "uac": ["T1012"],
    "user_desc": ["T1087.002"],
    "veeam": ["T1552.001"],
    "vnc": ["T1552.002"],
    "wam": ["T1528"],
    "wcc": ["T1046"],
    "wdigest": ["T1112"],
    "web_delivery": ["T1105"],
    "webdav": ["T1046"],
    "whoami": ["T1033"],
    "wifi": ["T1552.001"],
    "winscp": ["T1552.002"],
    "zerologon": ["T1210"],
}


def get_base_attack_patterns(protocol: str) -> list[str]:
    """MITRE ATT&CK technique ids for a base protocol contract."""
    return list(_BASE_ATTACK_PATTERNS.get(protocol, []))


def get_option_attack_patterns(option_id: str) -> list[str]:
    """MITRE ATT&CK technique ids for an (protocol, option) contract."""
    return list(_OPTION_ATTACK_PATTERNS.get(option_id, []))


def get_module_attack_patterns(safe_module_key: str) -> list[str]:
    """MITRE ATT&CK technique ids for a (protocol, module) contract."""
    return list(_MODULE_ATTACK_PATTERNS.get(safe_module_key, []))
