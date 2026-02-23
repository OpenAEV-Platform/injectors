"""Registry mapping each contract to its output parser types.

Each option/module is mapped to a set of output types it can produce.
This drives both:
  - which ``ContractOutputElement`` are declared on each contract
  - which extractors the parser runs after execution

To add a new mapping, simply add the identifier to the appropriate set below.
Contracts not listed here default to ``{"text"}`` (generic text output).
Contracts in ``_NO_OUTPUT`` produce no structured findings at all.
"""

# ---------------------------------------------------------------------------
# Output type constants
# ---------------------------------------------------------------------------
TEXT = "text"
CREDENTIALS = "credentials"
USERNAME = "username"
SHARE = "share"
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

# ---------------------------------------------------------------------------
# Options that produce NO structured output (actions, config toggles)
# ---------------------------------------------------------------------------
_NO_OUTPUT_OPTIONS = {
    "local_auth",       # just a flag, no extra output
    "no_output",        # explicitly no output
    "screenshot",       # binary file, not parseable text
    "nla_screenshot",   # binary file
    "sudo_check",       # pass/fail only
    "bloodhound",       # produces JSON files, not stdout
}

# ---------------------------------------------------------------------------
# Options → output types
# ---------------------------------------------------------------------------
_OPTION_OUTPUTS = {
    # Credential dumps
    "sam":           {CREDENTIALS, TEXT},
    "lsa":           {CREDENTIALS, TEXT},
    "ntds":          {CREDENTIALS, TEXT},
    "gmsa":          {CREDENTIALS, TEXT},
    "asreproast":    {ASREPROASTABLE, TEXT},
    "kerberoasting": {KERBEROASTABLE, TEXT},

    # Enumeration (text + possible credential leaks in descriptions)
    "users":                  {TEXT, CREDENTIALS, USERNAME},
    "groups":                 {TEXT, GROUP},
    "local_groups":           {TEXT, GROUP},
    "loggedon_users":         {TEXT, USERNAME},
    "computers":              {TEXT, COMPUTER},
    "rid_brute":              {TEXT, USERNAME},
    "active_users":           {TEXT, CREDENTIALS, USERNAME},
    "trusted_for_delegation": {TEXT, DELEGATION},
    "find_delegation":        {TEXT, DELEGATION},
    "password_not_required":  {TEXT, ACCOUNT_PW_NOT_REQUIRED},
    "admin_count":            {TEXT, ADMIN_USERNAME},
    "dc_list":                {TEXT},
    "get_sid":                {TEXT, SID},
    # Shares / disks / files
    "shares":       {TEXT, SHARE},
    "enum_shares":  {TEXT},
    "disks":        {TEXT},
    "interfaces":   {TEXT},
    "ls":           {TEXT},

    # Password policy
    "pass_pol": {TEXT, PASSWORD_POLICY},
}

# ---------------------------------------------------------------------------
# Modules → output types
# ---------------------------------------------------------------------------
_MODULE_OUTPUTS = {
    # Credential-dumping modules
    "lsassy":             {CREDENTIALS, TEXT},
    "handlekatz":         {CREDENTIALS, TEXT},
    "procdump":           {CREDENTIALS, TEXT},
    "nanodump":           {CREDENTIALS, TEXT},
    "hash_spider":        {CREDENTIALS, TEXT},
    "dpapi_hash":         {CREDENTIALS, TEXT},
    "gpp_password":       {CREDENTIALS, TEXT},
    "gpp_autologin":      {CREDENTIALS, TEXT},
    "masky":              {CREDENTIALS, TEXT},
    "ntdsutil":           {CREDENTIALS, TEXT},
    "msol":               {CREDENTIALS, TEXT},
    "wam":                {CREDENTIALS, TEXT},
    "wifi":               {CREDENTIALS, TEXT},
    "winscp":             {CREDENTIALS, TEXT},
    "mremoteng":          {CREDENTIALS, TEXT},
    "mobaxterm":          {CREDENTIALS, TEXT},
    "rdcman":             {CREDENTIALS, TEXT},
    "firefox":            {CREDENTIALS, TEXT},
    "iis":                {CREDENTIALS, TEXT},
    "keepass_discover":   {CREDENTIALS, TEXT},
    "keepass_trigger":    {CREDENTIALS, TEXT},
    "veeam":              {CREDENTIALS, TEXT},
    "vnc":                {CREDENTIALS, TEXT},
    "putty":              {CREDENTIALS, TEXT},
    "teams_localdb":      {CREDENTIALS, TEXT},
    "notepadplusplus":    {CREDENTIALS, TEXT},
    "snipped":            {CREDENTIALS, TEXT},
    "powershell_history": {CREDENTIALS, TEXT},
    "reg_winlogon":       {CREDENTIALS, TEXT},
    "security_questions": {CREDENTIALS, TEXT},
    "backup_operator":    {CREDENTIALS, TEXT},

    # User / group / AD enumeration
    "get_desc_users":        {TEXT, CREDENTIALS},
    "user_desc":             {TEXT, CREDENTIALS},
    "find_computer":         {TEXT},
    "groupmembership":       {TEXT},
    "group_mem":             {TEXT},
    "whoami":                {TEXT},
    "pre2k":                 {TEXT, CREDENTIALS},
    "obsolete":              {TEXT},
    "enum_logins":           {TEXT},
    "pso":                   {TEXT},
    "maq":                   {TEXT},

    # Vulnerability / exploit detection
    "ms17_010":       {TEXT},
    "smbghost":       {TEXT},
    "zerologon":      {TEXT},
    "nopac":          {TEXT},
    "printnightmare": {TEXT},
    "petitpotam":     {TEXT},
    "shadowcoerce":   {TEXT},
    "dfscoerce":      {TEXT},
    "coerce_plus":    {TEXT, VULNERABILITY},
    "printerbug":     {TEXT},
    "spooler":        {TEXT, VULNERABILITY},
    "webdav":         {TEXT},
    "ntlmv1":         {TEXT},
    "ldap_checker":   {TEXT, VULNERABILITY},
    "timeroast":      {TEXT},

    # Network / infra enumeration
    "get_network":       {TEXT},
    "subnets":           {TEXT},
    "enum_dns":          {TEXT},
    "ioxidresolver":     {TEXT},
    "get_netconnections": {TEXT},
    "bitlocker":         {TEXT},
    "enum_ca":           {TEXT},
    "enum_av":           {TEXT},
    "adcs":              {TEXT},
    "sccm":              {TEXT},
    "hyperv_host":       {TEXT},
    "uac":               {TEXT},
    "wcc":               {TEXT},
    "recent_files":      {TEXT},

    # File spider
    "spider_plus": {TEXT},

    # Actions (execute something, limited stdout findings)
    "add_computer":      {TEXT},
    "empire_exec":       {TEXT},
    "met_inject":        {TEXT},
    "web_delivery":      {TEXT},
    "schtask_as":        {TEXT},
    "drop_sc":           {TEXT},
    "scuffy":            {TEXT},
    "slinky":            {TEXT},
    "impersonate":       {TEXT},
    "pi":                {TEXT},
    "install_elevated":  {TEXT},
    "remove_mic":        {TEXT},
    "rdp":               {TEXT},
    "shadowrdp":         {TEXT},
    "wdigest":           {TEXT},
    "runasppl":          {TEXT},
    "remote_uac":        {TEXT},
    "reg_query":         {TEXT},
    "daclread":          {TEXT},
    "mssql_priv":        {TEXT},
    "enum_impersonate":  {TEXT},
    "enum_links":        {TEXT},
    "exec_on_link":      {TEXT},
    "link_xpcmd":        {TEXT},
    "link_enable_cmdshell": {TEXT},
    "mssql_coerce":      {TEXT},
    "test_connection":   {TEXT},
    "badsuccessor":      {TEXT},
    "raisechild":        {TEXT},
    "notepad":           {TEXT},
    "recyclebin":        {TEXT},
    "enable_cmdshell":   {TEXT},
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_option_output_types(option_id: str) -> set[str]:
    """Return the set of output types for a given option contract."""
    if option_id in _NO_OUTPUT_OPTIONS:
        return set()
    return _OPTION_OUTPUTS.get(option_id, {TEXT})


def get_module_output_types(safe_module_key: str) -> set[str]:
    """Return the set of output types for a given module contract."""
    return _MODULE_OUTPUTS.get(safe_module_key, {TEXT})


def get_base_output_types() -> set[str]:
    """Base protocol contracts can produce text output (command execution)."""
    return {TEXT}
