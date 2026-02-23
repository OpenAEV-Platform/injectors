"""NetExec modules registry - maps all modules to their protocols and options."""

from typing import Dict, List, Optional


def _mod(name: str, label: str, protocols: List[str], options: Dict = None) -> Dict:
    return {
        "name": name,
        "label": label,
        "protocols": protocols,
        "options": options or {},
    }


def _opt(desc: str, required: bool = False) -> Dict:
    return {"desc": desc, "required": required}


# ---------------------------------------------------------------------------
# Complete NetExec modules registry (sorted alphabetically)
# ---------------------------------------------------------------------------
NETEXEC_MODULES: List[Dict] = [
    # ---- A ----
    _mod("add-computer", "Add/delete a domain computer", ["smb"], {
        "NAME": _opt("Computer name to add", True),
        "PASSWORD": _opt("Password for the computer account"),
        "DELETE": _opt("Remove a computer account (True/False)"),
        "CHANGEPW": _opt("Modify existing computer password (True/False)"),
    }),
    _mod("adcs", "PKI Enrollment Services enumeration", ["ldap"], {
        "SERVER": _opt("PKI Enrollment Server to enumerate"),
        "BASE_DN": _opt("Base domain name for LDAP query"),
    }),
    # ---- B ----
    _mod("backup_operator", "Exploit backup operator group to dump NTDS", ["smb"]),
    _mod("bitlocker", "Enumerate BitLocker status", ["smb", "wmi"]),
    # ---- C ----
    _mod("coerce_plus", "Check coerce vulnerabilities", ["smb"], {
        "LISTENER": _opt("Listener IP for exploitation"),
        "ALWAYS": _opt("Always continue to all exploits (True/False)"),
        "METHOD": _opt("Method: Petitpotam, DFSCoerce, ShadowCoerce, Printerbug, MSEven, All"),
    }),
    # ---- D ----
    _mod("daclread", "Read/backup DACL of objects", ["ldap"], {
        "TARGET": _opt("Object SamAccountName to read DACL"),
        "TARGET_DN": _opt("Object DN to read DACL"),
        "PRINCIPAL": _opt("Trustee to filter on"),
        "ACTION": _opt("Action: read or backup"),
        "ACE_TYPE": _opt("ACE type: allowed or denied"),
        "RIGHTS": _opt("Rights filter: FullControl, ResetPassword, WriteMembers, DCSync"),
        "RIGHTS_GUID": _opt("Right GUID to filter"),
    }),
    _mod("dfscoerce", "[Removed] Check DFSCoerce vulnerability", ["smb"], {
        "LISTENER": _opt("Listener address"),
    }),
    _mod("dpapi_hash", "Remotely dump DPAPI hashes", ["smb"], {
        "OUTPUTFILE": _opt("Output file to write hashes"),
    }),
    _mod("drop-sc", "Drop searchConnector-ms on writable shares", ["smb"], {
        "URL": _opt("URL embedded in the file"),
        "CLEANUP": _opt("Execute cleanup (True/False)"),
        "SHARE": _opt("Target a specific share"),
        "FILENAME": _opt("Filename without extension"),
    }),
    # ---- E ----
    _mod("empire_exec", "Empire launcher execution", ["smb", "mssql"], {
        "LISTENER": _opt("Empire listener name", True),
        "SSL": _opt("Listener uses SSL (True/False)"),
        "OBFUSCATE": _opt("Use built-in obfuscation (True/False)"),
        "OBFUSCATE_CMD": _opt("Invoke-Obfuscation command override"),
    }),
    _mod("enum_av", "Enumerate endpoint protection solutions", ["smb"]),
    _mod("enum_ca", "Hunt for ADCS CAs via RPC", ["smb"]),
    _mod("enum_dns", "Dump DNS from AD DNS Server via WMI", ["smb", "wmi"], {
        "DOMAIN": _opt("Domain to enumerate DNS for"),
    }),
    _mod("enum_impersonate", "Enumerate impersonation privileges", ["mssql"]),
    _mod("enum_links", "Enumerate linked SQL Servers", ["mssql"]),
    _mod("enum_logins", "Enumerate SQL Server logins", ["mssql"]),
    _mod("enum_trusts", "[Removed] Extract trust relationships", ["ldap"]),
    _mod("exec_on_link", "Execute commands on linked SQL server", ["mssql"], {
        "LINKED_SERVER": _opt("Name of the linked server", True),
        "COMMAND": _opt("Command to execute", True),
    }),
    # ---- F ----
    _mod("find-computer", "Find computers by search text", ["ldap"], {
        "TEXT": _opt("Search text for OS or computer name", True),
    }),
    _mod("firefox", "[Removed] Dump Firefox credentials", ["smb"], {
        "COOKIES": _opt("Get Firefox cookies too (True/False)"),
    }),
    # ---- G ----
    _mod("get-desc-users", "Get user descriptions (may contain passwords)", ["ldap"], {
        "FILTER": _opt("Grep-like filter"),
        "PASSWORDPOLICY": _opt("Windows password policy enabled (True/False)"),
        "MINLENGTH": _opt("Minimum password length to match"),
    }),
    _mod("get-network", "Query DNS records with IPs from domain", ["ldap"], {
        "ALL": _opt("Get DNS and IP (True/False)"),
        "ONLY_HOSTS": _opt("Get DNS only, no IP (True/False)"),
    }),
    _mod("get-unixUserPassword", "Get unixUserPassword from LDAP users", ["ldap"]),
    _mod("get-userPassword", "Get userPassword from LDAP users", ["ldap"]),
    _mod("get_netconnections", "Query network connections via WMI", ["smb", "wmi"]),
    _mod("gpp_autologin", "Search for autologin info in registry.xml", ["smb"]),
    _mod("gpp_password", "Retrieve GPP plaintext passwords", ["smb"]),
    _mod("group-mem", "[Removed] Retrieve group members", ["ldap"], {
        "GROUP": _opt("Group to query for membership", True),
    }),
    _mod("groupmembership", "Query groups a user belongs to", ["ldap"], {
        "USER": _opt("Username to query group membership", True),
    }),
    # ---- H ----
    _mod("handlekatz", "Dump lsass with handlekatz64 + pypykatz", ["smb"], {
        "TMP_DIR": _opt("Path on target for dump"),
        "HANDLEKATZ_PATH": _opt("Path to handlekatz.exe on your system"),
        "HANDLEKATZ_EXE_NAME": _opt("Executable name"),
        "DIR_RESULT": _opt("Location for dump files"),
    }),
    _mod("hash_spider", "Recursive lsass dump via BloodHound local admins", ["smb"], {
        "METHOD": _opt("lsassy dump method"),
        "RESET_DUMPED": _opt("Allow re-dumping hosts (True/False)"),
        "RESET": _opt("Reset DB (True/False)"),
    }),
    _mod("hyperv-host", "Lookup HyperV Host from VM registry", ["smb"]),
    # ---- I ----
    _mod("iis", "Check IIS Application Pool credentials", ["smb"]),
    _mod("impersonate", "List/impersonate tokens for command execution", ["smb"], {
        "TOKEN": _opt("Token identifier to usurp"),
        "EXEC": _opt("Command to execute"),
        "IMP_EXE": _opt("Path to Impersonate binary"),
    }),
    _mod("install_elevated", "Check AlwaysInstallElevated", ["smb"]),
    _mod("ioxidresolver", "Identify hosts with additional interfaces", ["smb", "wmi"], {
        "DIFFERENT": _opt("Show only IP if different from target (true/false)"),
    }),
    # ---- K ----
    _mod("keepass_discover", "Search for KeePass files and processes", ["smb"], {
        "SEARCH_TYPE": _opt("PROCESS, FILES, or ALL"),
        "SEARCH_PATH": _opt("Paths to search"),
    }),
    _mod("keepass_trigger", "Set up malicious KeePass trigger for export", ["smb"], {
        "ACTION": _opt("ADD, CHECK, RESTART, POLL, CLEAN, or ALL", True),
        "KEEPASS_CONFIG_PATH": _opt("Remote KeePass config path"),
        "USER": _opt("Target user running KeePass"),
        "EXPORT_NAME": _opt("Export file name"),
        "EXPORT_PATH": _opt("Export path"),
        "PSH_EXEC_METHOD": _opt("PowerShell method: ENCODE or PS1"),
    }),
    # ---- L ----
    _mod("laps", "Retrieve LAPS passwords", ["ldap"], {
        "COMPUTER": _opt("Computer name or wildcard (default: *)"),
    }),
    _mod("ldap-checker", "[Removed] Check LDAP signing and channel binding", ["ldap"]),
    _mod("link_xpcmd", "Run xp_cmdshell on linked SQL server", ["mssql"], {
        "LINKED_SERVER": _opt("Name of the linked SQL server", True),
        "CMD": _opt("Command to run via xp_cmdshell", True),
    }),
    _mod("lsassy", "Dump lsass remotely with lsassy", ["smb"], {
        "METHOD": _opt("Method to dump lsass.exe"),
        "DUMP_TICKETS": _opt("Dump Kerberos tickets (True/False)"),
        "SAVE_DIR": _opt("Directory to save tickets"),
        "SAVE_TYPE": _opt("Ticket type: kirbi or ccache"),
    }),
    # ---- M ----
    _mod("maq", "Retrieve MachineAccountQuota attribute", ["ldap"]),
    _mod("masky", "Dump domain creds via ADCS and KDC", ["smb"], {
        "CA": _opt("Certificate Authority (CA_SERVER\\CA_NAME)"),
        "TEMPLATE": _opt("Template for user authentication"),
        "DC_IP": _opt("IP of the domain controller"),
        "AGENT_EXE": _opt("Path to custom masky agent"),
    }),
    _mod("met_inject", "Inject Meterpreter stager into memory", ["smb", "mssql"], {
        "SRVHOST": _opt("IP hosting the stager server", True),
        "SRVPORT": _opt("Stager port", True),
        "RAND": _opt("Random string from metasploit"),
        "SSL": _opt("Protocol: https or http"),
    }),
    _mod("mobaxterm", "Dump MobaXterm credentials remotely", ["smb"]),
    _mod("mremoteng", "Dump mRemoteNG passwords", ["smb"], {
        "SHARE": _opt("Share parsed for connection"),
        "PASSWORD": _opt("Custom password to decrypt confCons.xml"),
        "CUSTOM_PATH": _opt("Custom path to confCons.xml"),
    }),
    _mod("ms17-010", "Check EternalBlue vulnerability", ["smb"]),
    _mod("msol", "Dump MSOL/Entra ID creds from local DB", ["smb"]),
    _mod("mssql_coerce", "SQL coercion/exfiltration via listener", ["mssql"], {
        "LISTENER": _opt("Listener IP for exploitation", True),
    }),
    _mod("mssql_priv", "Enumerate and exploit MSSQL privileges", ["mssql"], {
        "ACTION": _opt("enum_priv, privesc, or rollback"),
    }),
    # ---- N ----
    _mod("nanodump", "Dump lsass with nanodump + pypykatz", ["smb", "mssql"], {
        "TMP_DIR": _opt("Path on target for dump"),
        "NANO_PATH": _opt("Path to nano.exe on your system"),
        "NANO_EXE_NAME": _opt("Executable name"),
        "DIR_RESULT": _opt("Location for dump files"),
    }),
    _mod("nopac", "Check CVE-2021-42278/42287 (noPac)", ["smb"]),
    _mod("notepad++", "Extract notepad++ unsaved files", ["smb"]),
    _mod("ntdsutil", "Dump NTDS with ntdsutil", ["smb"], {
        "DIR_RESULT": _opt("Local dir to write ntds dump"),
    }),
    _mod("ntlmv1", "Detect NTLMv1 enabled (lmcompatibilitylevel < 3)", ["smb"]),
    # ---- O ----
    _mod("obsolete", "Extract obsolete OS from LDAP", ["ldap"]),
    # ---- P ----
    _mod("petitpotam", "[Removed] Check PetitPotam vulnerability", ["smb"], {
        "LISTENER": _opt("Listener IP"),
        "PIPE": _opt("Named pipe (default: lsarpc)"),
    }),
    _mod("pi", "Process injection - run command as logged user", ["smb"], {
        "PID": _opt("Process ID for target user", True),
        "EXEC": _opt("Command to execute", True),
    }),
    _mod("powershell_history", "Extract PowerShell history for all users", ["smb"], {
        "EXPORT": _opt("Write history files to disk (True/False)"),
    }),
    _mod("pre2k", "Identify pre-created computer accounts", ["ldap"]),
    _mod("printerbug", "[Removed] Check PrinterBug vulnerability", ["smb"], {
        "LISTENER": _opt("Listener address"),
    }),
    _mod("printnightmare", "Check PrintNightmare vulnerability", ["smb"], {
        "PORT": _opt("Port to check"),
    }),
    _mod("procdump", "Dump lsass with procdump64 + pypykatz", ["smb"], {
        "TMP_DIR": _opt("Path on target for dump"),
        "PROCDUMP_PATH": _opt("Path to procdump.exe"),
        "PROCDUMP_EXE_NAME": _opt("Executable name"),
        "DIR_RESULT": _opt("Location for dump files"),
    }),
    _mod("pso", "Get Fine Grained Password Policy/PSOs", ["ldap"]),
    _mod("putty", "Query registry for PuTTY SSH private keys", ["smb"]),
    # ---- R ----
    _mod("rdcman", "Dump Remote Desktop Connection Manager creds", ["smb"]),
    _mod("rdp", "Enable/Disable RDP", ["smb", "wmi"], {
        "ACTION": _opt("enable, disable, enable-ram, disable-ram", True),
        "METHOD": _opt("wmi or smb"),
        "OLD": _opt("For old systems under NT6 (True/False)"),
        "DCOM-TIMEOUT": _opt("DCOM connection timeout in seconds"),
    }),
    _mod("recent_files", "Extract recently modified files", ["smb"]),
    _mod("reg-query", "Perform a registry query", ["smb"], {
        "PATH": _opt("Registry key path", True),
        "KEY": _opt("Registry key value to retrieve", True),
        "VALUE": _opt("Registry key value to set"),
        "TYPE": _opt("Registry type (default: REG_SZ)"),
        "DELETE": _opt("Delete registry key (True/False)"),
    }),
    _mod("reg-winlogon", "Collect autologon credentials from registry", ["smb"]),
    _mod("remote-uac", "Enable or disable remote UAC", ["smb"], {
        "ACTION": _opt("enable or disable", True),
    }),
    _mod("remove-mic", "Check CVE-2019-1040 vulnerability", ["smb"], {
        "PORT": _opt("Port to check"),
    }),
    _mod("runasppl", "Check RunAsPPL registry value", ["smb"]),
    # ---- S ----
    _mod("sccm", "Find SCCM infrastructure in AD", ["ldap"], {
        "BASE_DN": _opt("Base domain name for LDAP query"),
        "REC_RESOLVE": _opt("Resolve group members recursively (True/False)"),
    }),
    _mod("schtask_as", "Execute scheduled task as logged on user", ["smb"], {
        "CMD": _opt("Command to execute", True),
        "USER": _opt("User to execute as", True),
        "BINARY": _opt("Upload binary for CMD execution"),
        "TASK": _opt("Scheduled task name"),
        "FILE": _opt("Output filename"),
        "LOCATION": _opt("Output file location"),
        "SILENTCOMMAND": _opt("Suppress output retrieval (True/False)"),
        "CA": _opt("Certificate Authority"),
        "TEMPLATE": _opt("Certificate template name"),
    }),
    _mod("scuffy", "Create/upload .scf for NTLMv2 hash looting", ["smb"], {
        "SERVER": _opt("SMB server IP", True),
        "NAME": _opt("SCF file name", True),
        "CLEANUP": _opt("Cleanup mode (True/False)"),
    }),
    _mod("security-questions", "Get security questions and answers", ["smb"]),
    _mod("shadowcoerce", "[Removed] Check ShadowCoerce vulnerability", ["smb"], {
        "IPSC": _opt("Use IsPathShadowCopied (True/False)"),
        "LISTENER": _opt("Listener IP address"),
    }),
    _mod("shadowrdp", "Enable/disable shadow RDP", ["smb"], {
        "ACTION": _opt("enable or disable", True),
    }),
    _mod("slinky", "Create LNK shortcuts with UNC icon on shares", ["smb"], {
        "SERVER": _opt("Listening server IP", True),
        "NAME": _opt("LNK file name", True),
        "ICO_URI": _opt("Override full ICO path"),
        "SHARES": _opt("Specific shares (comma-separated)"),
        "IGNORE": _opt("Shares to ignore (comma-separated)"),
        "CLEANUP": _opt("Cleanup mode (True/False)"),
    }),
    _mod("smbghost", "Check SMBGhost CVE-2020-0796", ["smb"]),
    _mod("snipped", "Download Snipping Tool screenshots", ["smb"], {
        "USERS": _opt("Download only specified user(s)"),
    }),
    _mod("spider_plus", "Recursively list/download share files", ["smb"], {
        "DOWNLOAD_FLAG": _opt("Download all share files (True/False)"),
        "STATS_FLAG": _opt("Disable file/download statistics (True/False)"),
        "EXCLUDE_EXTS": _opt("Extensions to exclude (comma-separated)"),
        "EXCLUDE_FILTER": _opt("Folders/files to exclude (comma-separated)"),
        "MAX_FILE_SIZE": _opt("Max file size to download (bytes)"),
        "OUTPUT_FOLDER": _opt("Local folder for output"),
    }),
    _mod("spooler", "Detect print spooler status", ["smb", "wmi"], {
        "PORT": _opt("Port to check"),
    }),
    _mod("subnets", "Retrieve AD Sites and Subnets", ["ldap"], {
        "SHOWSERVERS": _opt("Toggle printing of servers (True/False)"),
    }),
    # ---- T ----
    _mod("teams_localdb", "Retrieve Teams ssoauthcookie from local DB", ["smb"]),
    _mod("test_connection", "Ping a host", ["smb", "mssql"], {
        "HOST": _opt("Host to ping", True),
    }),
    _mod("timeroast", "Timeroasting - request password hashes via NTP", ["smb"], {
        "rids": _opt("RID sequence to query"),
        "rate": _opt("Queries per second"),
        "timeout": _opt("Seconds before giving up"),
        "src_port": _opt("Source port for UDP socket"),
        "old_hashes": _opt("Old vs new password mode (True/False)"),
    }),
    # ---- U ----
    _mod("uac", "Check UAC status", ["smb"]),
    _mod("user-desc", "Get user descriptions from AD", ["ldap"], {
        "LDAP_FILTER": _opt("Custom LDAP search filter"),
        "DESC_FILTER": _opt("Filter for descriptions (wildcard *)"),
        "DESC_INVERT": _opt("Inverse filter for descriptions"),
        "USER_FILTER": _opt("Filter for usernames (wildcard *)"),
        "USER_INVERT": _opt("Inverse filter for usernames"),
        "KEYWORDS": _opt("Custom keyword set (comma-separated)"),
        "ADD_KEYWORDS": _opt("Additional keywords (comma-separated)"),
    }),
    # ---- V ----
    _mod("veeam", "Extract Veeam credentials from local SQL DB", ["smb"]),
    _mod("vnc", "Loot VNC server and client passwords", ["smb"], {
        "NO_REMOTEOPS": _opt("Do not use RemoteRegistry (True/False)"),
    }),
    # ---- W ----
    _mod("wam", "Dump access tokens from Token Broker Cache", ["smb"]),
    _mod("wcc", "Check Windows security configuration", ["smb"], {
        "OUTPUT_FORMAT": _opt("Report format: json or csv"),
        "OUTPUT": _opt("Path for report file"),
        "QUIET": _opt("Do not print to stdout (true/false)"),
    }),
    _mod("wdigest", "Enable/disable WDigest credential dumping", ["smb"], {
        "ACTION": _opt("enable, disable, or check", True),
    }),
    _mod("web_delivery", "Metasploit web_delivery module execution", ["smb", "mssql"], {
        "URL": _opt("URL for the download cradle", True),
        "PAYLOAD": _opt("Payload architecture: 64 or 32"),
    }),
    _mod("webdav", "Check WebClient service status", ["smb"], {
        "MSG": _opt("Custom message output"),
    }),
    _mod("whoami", "Get details of provided user", ["ldap"], {
        "USER": _opt("SamAccountName to enumerate"),
    }),
    _mod("wifi", "Get wireless interface keys", ["smb"]),
    _mod("winscp", "Extract WinSCP credentials from registry", ["smb"], {
        "PATH": _opt("Path to WinSCP.ini"),
    }),
    # ---- Z ----
    _mod("zerologon", "Check Zerologon CVE-2020-1472", ["smb", "wmi"]),
]


def get_modules_for_protocol(protocol: str) -> List[Dict]:
    """Return all modules that support the given protocol, sorted by name."""
    return sorted(
        [m for m in NETEXEC_MODULES if protocol in m["protocols"]],
        key=lambda m: m["name"],
    )


def safe_module_key(name: str) -> str:
    """Convert module name to a safe key component for contract field keys."""
    return name.replace("-", "_").replace("+", "plus")


def get_module_by_safe_key(protocol: str, safe_key: str) -> Optional[Dict]:
    """Look up a module by its safe_module_key for a given protocol.

    Returns ``None`` if no matching module is found.
    """
    for m in NETEXEC_MODULES:
        if protocol in m["protocols"] and safe_module_key(m["name"]) == safe_key:
            return m
    return None
