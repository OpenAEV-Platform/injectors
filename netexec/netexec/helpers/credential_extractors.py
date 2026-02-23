"""Per-contract credential extractors for NetExec output parsing.

Each extractor is a callable: (finding_lines, ip_to_asset_id_map) -> List[Dict]

IMPORTANT: Every contract MUST have its own dedicated extractor function.
Never share an extractor between contracts — even if the regex is identical
today, output formats can diverge and a shared function would silently
produce wrong findings on one contract when the other changes.

The registry maps (family, identifier) to the appropriate extractor.
Contracts without a specific extractor fall back to the generic
``_PASSWORD_LEAK`` regex in the output parser (or nothing if they don't
declare CREDENTIALS in the output registry).

New extractors are added here -- either manually or via the
``/add-output-parser`` skill -- as real stdout samples become available.
"""

import re
from typing import Dict, List, Tuple


# ---------------------------------------------------------------------------
# Helper used internally by extractor functions (NOT shared as an extractor)
# ---------------------------------------------------------------------------

def _extract_password_from_description(
    finding_lines: List[Tuple[str, str, str]],
    ip_to_asset_id_map: Dict,
    password_re: re.Pattern,
    username_re: re.Pattern,
) -> List[Dict]:
    """Internal helper — extracts credentials from lines matching the given
    password and username regexes. Each extractor function calls this with
    its own compiled patterns."""
    results: List[Dict] = []
    for ip, hostname, rest in finding_lines:
        m = password_re.search(rest)
        if not m:
            continue
        password = m.group("pw1") or m.group("pw2") or m.group("pw3")
        if not password:
            continue

        username = ""
        user_match = username_re.search(rest)
        if user_match:
            username = user_match.group(1)

        credential: Dict = {
            "username": username,
            "password": password.strip(),
            "host": ip,
            "hostname": hostname,
            "source_line": rest,
        }

        asset_id = ip_to_asset_id_map.get(ip, "")
        if asset_id:
            credential["asset_id"] = asset_id

        results.append(credential)
    return results


def extract_no_credentials(
    finding_lines: List[Tuple[str, str, str]],
    ip_to_asset_id_map: Dict,
) -> List[Dict]:
    """Explicitly produce no credentials.

    Used for contracts whose output format is not yet analysed, or that
    should never produce credential findings.
    """
    return []


# ===================================================================
# Per-contract extractors — ONE function per contract, never shared
# ===================================================================


# -------------------------------------------------------------------
# Option: users (smb --users / ldap --users)
# -------------------------------------------------------------------
# Example:  samwell.tarly  2025-12-11 10:33:21  0  Samwell Tarly (Password : Heartsbane)

_OPT_USERS_PW_RE = re.compile(
    r"(?i)(?:"
    r"\(Password\s*:\s*(?P<pw1>[^)]+)\)"
    r"|password\s*[=:]\s*(?P<pw2>\S+)"
    r"|pwd\s*[=:]\s*(?P<pw3>\S+)"
    r")"
)
_OPT_USERS_USER_RE = re.compile(r"^\s*(\S+)\s+\d{4}-\d{2}-\d{2}")


def extract_opt_users_credentials(
    finding_lines: List[Tuple[str, str, str]],
    ip_to_asset_id_map: Dict,
) -> List[Dict]:
    """Extract credentials from ``--users`` option output.

    Line format::
        samwell.tarly  2025-12-11 10:33:21  0  Samwell Tarly (Password : Heartsbane)
    """
    return _extract_password_from_description(
        finding_lines, ip_to_asset_id_map,
        _OPT_USERS_PW_RE, _OPT_USERS_USER_RE,
    )


# -------------------------------------------------------------------
# Option: active_users (ldap --active-users)
# -------------------------------------------------------------------
# Same format as --users but should NOT produce credentials.
# The output lists active users; a password match here would be
# coincidental (e.g. ":Heartsbane" without context).

def extract_opt_active_users_credentials(
    finding_lines: List[Tuple[str, str, str]],
    ip_to_asset_id_map: Dict,
) -> List[Dict]:
    """``--active-users`` — no credential extraction."""
    return []


# -------------------------------------------------------------------
# Module: get_desc_users
# -------------------------------------------------------------------
# Example:  User: samwell.tarly description: Samwell Tarly (Password : Heartsbane)

_MOD_GET_DESC_USERS_PW_RE = re.compile(
    r"(?i)(?:"
    r"\(Password\s*:\s*(?P<pw1>[^)]+)\)"
    r"|password\s*[=:]\s*(?P<pw2>\S+)"
    r"|pwd\s*[=:]\s*(?P<pw3>\S+)"
    r")"
)
_MOD_GET_DESC_USERS_USER_RE = re.compile(r"(?i)User:\s*(\S+)")


def extract_mod_get_desc_users_credentials(
    finding_lines: List[Tuple[str, str, str]],
    ip_to_asset_id_map: Dict,
) -> List[Dict]:
    """Extract credentials from ``get-desc-users`` module output.

    Line format::
        User: samwell.tarly description: Samwell Tarly (Password : Heartsbane)
    """
    return _extract_password_from_description(
        finding_lines, ip_to_asset_id_map,
        _MOD_GET_DESC_USERS_PW_RE, _MOD_GET_DESC_USERS_USER_RE,
    )


# -------------------------------------------------------------------
# Module: user_desc
# -------------------------------------------------------------------
# Example:  User: samwell.tarly - Description: Samwell Tarly (Password : Heartsbane)

_MOD_USER_DESC_PW_RE = re.compile(
    r"(?i)(?:"
    r"\(Password\s*:\s*(?P<pw1>[^)]+)\)"
    r"|password\s*[=:]\s*(?P<pw2>\S+)"
    r"|pwd\s*[=:]\s*(?P<pw3>\S+)"
    r")"
)
_MOD_USER_DESC_USER_RE = re.compile(r"(?i)User:\s*(\S+)")


def extract_mod_user_desc_credentials(
    finding_lines: List[Tuple[str, str, str]],
    ip_to_asset_id_map: Dict,
) -> List[Dict]:
    """Extract credentials from ``user-desc`` module output.

    Line format::
        User: samwell.tarly - Description: Samwell Tarly (Password : Heartsbane)
    """
    return _extract_password_from_description(
        finding_lines, ip_to_asset_id_map,
        _MOD_USER_DESC_PW_RE, _MOD_USER_DESC_USER_RE,
    )


# -------------------------------------------------------------------
# Option: sam (smb --sam)
# -------------------------------------------------------------------
# Example:  Administrator:500:aad3b435b51404eeaad3b435b51404ee:dbd13e1c4e338284ac4e9874f7de6ef4:::

_OPT_SAM_HASH_RE = re.compile(
    r"^(?P<username>[^:]+):(?P<rid>\d+):"
    r"(?P<lm_hash>[a-f0-9]{32}):"
    r"(?P<nt_hash>[a-f0-9]{32}):::\s*$"
)


def extract_opt_sam_credentials(
    finding_lines: List[Tuple[str, str, str]],
    ip_to_asset_id_map: Dict,
) -> List[Dict]:
    """Extract credentials from ``--sam`` option output.

    Line format::
        Administrator:500:aad3b435b51404eeaad3b435b51404ee:dbd13e1c4e338284ac4e9874f7de6ef4:::
    """
    results: List[Dict] = []
    for ip, hostname, rest in finding_lines:
        m = _OPT_SAM_HASH_RE.match(rest)
        if not m:
            continue
        credential: Dict = {
            "username": m.group("username"),
            "hash": f"{m.group('lm_hash')}:{m.group('nt_hash')}",
            "host": ip,
            "hostname": hostname,
            "source_line": rest,
        }
        asset_id = ip_to_asset_id_map.get(ip, "")
        if asset_id:
            credential["asset_id"] = asset_id
        results.append(credential)
    return results


# -------------------------------------------------------------------
# Option: lsa (smb --lsa)
# -------------------------------------------------------------------
# Multiple formats in a single output:
#   DOMAIN\USER$:aes256-cts-hmac-sha1-96:HEX       ← Kerberos AES256 key
#   DOMAIN\USER$:aes128-cts-hmac-sha1-96:HEX       ← Kerberos AES128 key
#   DOMAIN\USER$:des-cbc-md5:HEX                   ← Kerberos DES key
#   DOMAIN\USER$:plain_password_hex:HEX             ← Machine account password
#   DOMAIN\USER$:LMHASH:NTHASH:::                  ← NTLM hash
#   DOMAIN\user:cleartext_password                  ← Cleartext password
#   dpapi_machinekey:0xHEX                          ← SKIP (infra key)
#   dpapi_userkey:0xHEX                             ← SKIP (infra key)

# 1. Kerberos keys: DOMAIN\account:enc-type:hex
_OPT_LSA_KERBEROS_RE = re.compile(
    r"^(?P<account>[^:]+):"
    r"(?P<enc_type>aes256-cts-hmac-sha1-96|aes128-cts-hmac-sha1-96|des-cbc-md5):"
    r"(?P<key>[a-f0-9]+)\s*$"
)

# 2. Plain password hex: DOMAIN\account:plain_password_hex:hex
_OPT_LSA_PLAIN_HEX_RE = re.compile(
    r"^(?P<account>[^:]+):plain_password_hex:(?P<hex>[a-f0-9]+)\s*$"
)

# 3. NTLM hash: DOMAIN\account:lmhash:nthash:::
_OPT_LSA_NTLM_RE = re.compile(
    r"^(?P<account>[^:]+):"
    r"(?P<lm_hash>[a-f0-9]{32}):"
    r"(?P<nt_hash>[a-f0-9]{32}):::\s*$"
)

# 4. Cleartext: DOMAIN\user:password (NOT dpapi_, NOT [+])
_OPT_LSA_CLEARTEXT_RE = re.compile(
    r"^(?P<account>[^\s:]+\\[^\s:]+):(?P<password>.+)$"
)

# Lines to skip
_OPT_LSA_SKIP_RE = re.compile(
    r"^(?:dpapi_(?:machinekey|userkey):|\[\+\])"
)


def extract_opt_lsa_credentials(
    finding_lines: List[Tuple[str, str, str]],
    ip_to_asset_id_map: Dict,
) -> List[Dict]:
    """Extract credentials from ``--lsa`` option output.

    Handles multiple formats in sequence:
    1. Kerberos keys (aes256/aes128/des)
    2. Plain password hex
    3. NTLM hashes (lm:nt)
    4. Cleartext passwords (DOMAIN\\user:password)

    Skips dpapi_machinekey/dpapi_userkey and info lines.
    """
    results: List[Dict] = []
    for ip, hostname, rest in finding_lines:
        # Skip dpapi keys and info lines
        if _OPT_LSA_SKIP_RE.match(rest):
            continue

        credential: Dict = None

        # 1. Kerberos key
        m = _OPT_LSA_KERBEROS_RE.match(rest)
        if m:
            credential = {
                "username": m.group("account"),
                "hash": f"{m.group('enc_type')}:{m.group('key')}",
                "host": ip,
                "hostname": hostname,
                "source_line": rest,
            }

        # 2. Plain password hex
        if not credential:
            m = _OPT_LSA_PLAIN_HEX_RE.match(rest)
            if m:
                credential = {
                    "username": m.group("account"),
                    "hash": f"plain_password_hex:{m.group('hex')}",
                    "host": ip,
                    "hostname": hostname,
                    "source_line": rest,
                }

        # 3. NTLM hash
        if not credential:
            m = _OPT_LSA_NTLM_RE.match(rest)
            if m:
                credential = {
                    "username": m.group("account"),
                    "hash": f"{m.group('lm_hash')}:{m.group('nt_hash')}",
                    "host": ip,
                    "hostname": hostname,
                    "source_line": rest,
                }

        # 4. Cleartext password (tried last — most permissive)
        if not credential:
            m = _OPT_LSA_CLEARTEXT_RE.match(rest)
            if m:
                credential = {
                    "username": m.group("account"),
                    "password": m.group("password"),
                    "host": ip,
                    "hostname": hostname,
                    "source_line": rest,
                }

        if credential:
            asset_id = ip_to_asset_id_map.get(ip, "")
            if asset_id:
                credential["asset_id"] = asset_id
            results.append(credential)

    return results


# -------------------------------------------------------------------
# Option: ntds (smb --ntds)
# -------------------------------------------------------------------
# Example:  goadmin:500:aad3b435b51404eeaad3b435b51404ee:dbd13e1c4e338284ac4e9874f7de6ef4:::
# Same hash format as SAM but domain-wide dump.

_OPT_NTDS_HASH_RE = re.compile(
    r"^(?P<username>[^:]+):(?P<rid>\d+):"
    r"(?P<lm_hash>[a-f0-9]{32}):"
    r"(?P<nt_hash>[a-f0-9]{32}):::\s*$"
)


def extract_opt_ntds_credentials(
    finding_lines: List[Tuple[str, str, str]],
    ip_to_asset_id_map: Dict,
) -> List[Dict]:
    """Extract credentials from ``--ntds`` option output.

    Line format::
        goadmin:500:aad3b435b51404eeaad3b435b51404ee:dbd13e1c4e338284ac4e9874f7de6ef4:::
    """
    results: List[Dict] = []
    for ip, hostname, rest in finding_lines:
        m = _OPT_NTDS_HASH_RE.match(rest)
        if not m:
            continue
        credential: Dict = {
            "username": m.group("username"),
            "hash": f"{m.group('lm_hash')}:{m.group('nt_hash')}",
            "host": ip,
            "hostname": hostname,
            "source_line": rest,
        }
        asset_id = ip_to_asset_id_map.get(ip, "")
        if asset_id:
            credential["asset_id"] = asset_id
        results.append(credential)
    return results


# -------------------------------------------------------------------
# Option: asreproast (ldap --asreproast)
# -------------------------------------------------------------------
# Example:  $krb5asrep$23$brandon.stark@NORTH.SEVENKINGDOMS.LOCAL:1ae83ac0...

_OPT_ASREPROAST_RE = re.compile(
    r"^(?P<hash>\$krb5asrep\$\d+\$(?P<username>[^@]+)@[^:]+:.+)\s*$"
)


def extract_opt_asreproast_accounts(
    finding_lines: List[Tuple[str, str, str]],
    ip_to_asset_id_map: Dict,
) -> List[Dict]:
    """Extract AS-REP roastable accounts from ``--asreproast`` option output.

    Line format::
        $krb5asrep$23$brandon.stark@NORTH.SEVENKINGDOMS.LOCAL:salt$hash
    """
    results: List[Dict] = []
    seen: set = set()
    for ip, hostname, rest in finding_lines:
        m = _OPT_ASREPROAST_RE.match(rest)
        if not m:
            continue
        # Deduplicate — same hash can appear twice (stdout + file)
        hash_val = m.group("hash")
        if hash_val in seen:
            continue
        seen.add(hash_val)
        finding: Dict = {
            "username": m.group("username"),
            "hash": hash_val,
            "host": ip,
            "hostname": hostname,
            "source_line": rest,
        }
        asset_id = ip_to_asset_id_map.get(ip, "")
        if asset_id:
            finding["asset_id"] = asset_id
        results.append(finding)
    return results


# -------------------------------------------------------------------
# Option: kerberoasting (ldap --kerberoasting)
# -------------------------------------------------------------------
# Expected: $krb5tgs$23$*username$REALM$spn*$salt$hash
# No real stdout sample yet — placeholder.

_OPT_KERBEROASTING_RE = re.compile(
    r"^(?P<hash>\$krb5tgs\$\d+\$\*?(?P<username>[^$*@]+)[\$*@].+)\s*$"
)


def extract_opt_kerberoasting_accounts(
    finding_lines: List[Tuple[str, str, str]],
    ip_to_asset_id_map: Dict,
) -> List[Dict]:
    """Extract Kerberoastable accounts from ``--kerberoasting`` option output.

    Line format::
        $krb5tgs$23$*username$REALM$spn*$salt$hash
    """
    results: List[Dict] = []
    seen: set = set()
    for ip, hostname, rest in finding_lines:
        m = _OPT_KERBEROASTING_RE.match(rest)
        if not m:
            continue
        hash_val = m.group("hash")
        if hash_val in seen:
            continue
        seen.add(hash_val)
        finding: Dict = {
            "username": m.group("username"),
            "hash": hash_val,
            "host": ip,
            "hostname": hostname,
            "source_line": rest,
        }
        asset_id = ip_to_asset_id_map.get(ip, "")
        if asset_id:
            finding["asset_id"] = asset_id
        results.append(finding)
    return results


# -------------------------------------------------------------------
# Module: dpapi_hash (smb -M dpapi_hash)
# -------------------------------------------------------------------
# Example:  goadmin:$DPAPImk$1*1*S-1-5-21-...*des3*sha1*18000*hex*208*hex

_MOD_DPAPI_HASH_RE = re.compile(
    r"^(?P<username>[^:]+):(?P<hash>\$DPAPImk\$.+)\s*$"
)


def extract_mod_dpapi_hash_credentials(
    finding_lines: List[Tuple[str, str, str]],
    ip_to_asset_id_map: Dict,
) -> List[Dict]:
    """Extract credentials from ``dpapi_hash`` module output.

    Line format::
        goadmin:$DPAPImk$1*1*S-1-5-21-...*des3*sha1*18000*salt*208*hash
    """
    results: List[Dict] = []
    for ip, hostname, rest in finding_lines:
        m = _MOD_DPAPI_HASH_RE.match(rest)
        if not m:
            continue
        credential: Dict = {
            "username": m.group("username"),
            "hash": m.group("hash"),
            "host": ip,
            "hostname": hostname,
            "source_line": rest,
        }
        asset_id = ip_to_asset_id_map.get(ip, "")
        if asset_id:
            credential["asset_id"] = asset_id
        results.append(credential)
    return results


# ===================================================================
# Per-contract USERNAME extractors
# ===================================================================


# -------------------------------------------------------------------
# Option: users (smb --users / ldap --users)
# -------------------------------------------------------------------
# Example:  goadmin                       2026-02-17 09:40:12 0       Built-in account for administering the computer/domain

_OPT_USERS_USERNAME_RE = re.compile(
    r"^(?P<username>\S+)\s+(?P<last_pw_set>\S+(?:\s+\S+)?)\s+(?P<bad_pw>\d+)\s*(?P<description>.*)$"
)


def extract_opt_users_usernames(
    finding_lines: List[Tuple[str, str, str]],
    ip_to_asset_id_map: Dict,
) -> List[Dict]:
    """Extract usernames from ``--users`` option output.

    Line format::
        goadmin                       2026-02-17 09:40:12 0       Built-in account ...
        Guest                         <never>             0       Built-in account ...
    """
    results: List[Dict] = []
    for ip, hostname, rest in finding_lines:
        m = _OPT_USERS_USERNAME_RE.match(rest)
        if not m:
            continue
        finding: Dict = {
            "username": m.group("username"),
            "host": ip,
            "hostname": hostname,
            "source_line": rest,
        }
        asset_id = ip_to_asset_id_map.get(ip, "")
        if asset_id:
            finding["asset_id"] = asset_id
        results.append(finding)
    return results


# -------------------------------------------------------------------
# Option: active_users (ldap --active-users)
# -------------------------------------------------------------------
# Same line format as --users but only enabled accounts.
# Example:  arya.stark                    2025-12-11 11:32:45 0        Arya Stark

_OPT_ACTIVE_USERS_USERNAME_RE = re.compile(
    r"^(?P<username>\S+)\s+(?P<last_pw_set>\S+(?:\s+\S+)?)\s+(?P<bad_pw>\d+)\s*(?P<description>.*)$"
)


def extract_opt_active_users_usernames(
    finding_lines: List[Tuple[str, str, str]],
    ip_to_asset_id_map: Dict,
) -> List[Dict]:
    """Extract usernames from ``--active-users`` option output.

    Line format::
        arya.stark                    2025-12-11 11:32:45 0        Arya Stark
    """
    results: List[Dict] = []
    for ip, hostname, rest in finding_lines:
        m = _OPT_ACTIVE_USERS_USERNAME_RE.match(rest)
        if not m:
            continue
        finding: Dict = {
            "username": m.group("username"),
            "host": ip,
            "hostname": hostname,
            "source_line": rest,
        }
        asset_id = ip_to_asset_id_map.get(ip, "")
        if asset_id:
            finding["asset_id"] = asset_id
        results.append(finding)
    return results


# -------------------------------------------------------------------
# Option: rid_brute (smb --rid-brute)
# -------------------------------------------------------------------
# Example:  500: NORTH\goadmin (SidTypeUser)
# Only extract SidTypeUser entries (skip groups, aliases).

_OPT_RID_BRUTE_USERNAME_RE = re.compile(
    r"^(?P<rid>\d+):\s+(?P<domain>[^\\]+)\\(?P<username>\S+)\s+\(SidTypeUser\)\s*$"
)


def extract_opt_rid_brute_usernames(
    finding_lines: List[Tuple[str, str, str]],
    ip_to_asset_id_map: Dict,
) -> List[Dict]:
    """Extract usernames from ``--rid-brute`` option output.

    Line format::
        500: NORTH\\goadmin (SidTypeUser)
        512: NORTH\\Domain Admins (SidTypeGroup)   ← skipped

    Only SidTypeUser entries are extracted.
    """
    results: List[Dict] = []
    for ip, hostname, rest in finding_lines:
        m = _OPT_RID_BRUTE_USERNAME_RE.match(rest)
        if not m:
            continue
        finding: Dict = {
            "username": m.group("username"),
            "domain": m.group("domain"),
            "rid": m.group("rid"),
            "host": ip,
            "hostname": hostname,
            "source_line": rest,
        }
        asset_id = ip_to_asset_id_map.get(ip, "")
        if asset_id:
            finding["asset_id"] = asset_id
        results.append(finding)
    return results


# -------------------------------------------------------------------
# Option: loggedon_users (smb --loggedon-users)
# -------------------------------------------------------------------
# Example:  NORTH\goadmin                   logon_server: WINTERFELL

_OPT_LOGGEDON_USERS_USERNAME_RE = re.compile(
    r"^(?P<domain>[^\\]+)\\(?P<username>\S+)\s+logon_server:\s*(?P<logon_server>\S*)\s*$"
)


def extract_opt_loggedon_users_usernames(
    finding_lines: List[Tuple[str, str, str]],
    ip_to_asset_id_map: Dict,
) -> List[Dict]:
    """Extract usernames from ``--loggedon-users`` option output.

    Line format::
        NORTH\\goadmin                   logon_server: WINTERFELL
    """
    results: List[Dict] = []
    for ip, hostname, rest in finding_lines:
        m = _OPT_LOGGEDON_USERS_USERNAME_RE.match(rest)
        if not m:
            continue
        finding: Dict = {
            "username": m.group("username"),
            "domain": m.group("domain"),
            "host": ip,
            "hostname": hostname,
            "source_line": rest,
        }
        asset_id = ip_to_asset_id_map.get(ip, "")
        if asset_id:
            finding["asset_id"] = asset_id
        results.append(finding)
    return results


# ===================================================================
# Per-contract SHARE extractors
# ===================================================================


# -------------------------------------------------------------------
# Option: shares (smb --shares)
# -------------------------------------------------------------------
# Example:  NETLOGON        READ,WRITE      Logon server share
# Exclude:  ADMIN$, C$, IPC$ (administrative shares ending with $)
# Exclude:  shares with no permissions

_OPT_SHARES_RE = re.compile(
    r"^(?P<share>\S+)\s+(?P<permissions>(?:READ|WRITE)(?:,(?:READ|WRITE))*)\s*(?P<remark>.*)$"
)


def extract_opt_shares_shares(
    finding_lines: List[Tuple[str, str, str]],
    ip_to_asset_id_map: Dict,
) -> List[Dict]:
    """Extract shares from ``--shares`` option output.

    Line format::
        NETLOGON        READ,WRITE      Logon server share
        ADMIN$          READ,WRITE      Remote Admin          ← excluded (admin share)
        IPC$            READ            Remote IPC            ← excluded (admin share)

    Administrative shares (ending with ``$``) are excluded.
    Shares with no permissions are excluded.
    """
    results: List[Dict] = []
    for ip, hostname, rest in finding_lines:
        m = _OPT_SHARES_RE.match(rest)
        if not m:
            continue
        share_name = m.group("share")
        # Skip administrative shares (ending with $)
        if share_name.endswith("$"):
            continue
        finding: Dict = {
            "share_name": share_name,
            "permissions": m.group("permissions"),
            "host": ip,
            "hostname": hostname,
            "source_line": rest,
        }
        asset_id = ip_to_asset_id_map.get(ip, "")
        if asset_id:
            finding["asset_id"] = asset_id
        results.append(finding)
    return results


# ===================================================================
# Per-contract ADMIN_USERNAME extractors
# ===================================================================


# -------------------------------------------------------------------
# Option: admin_count (ldap --admin-count)
# -------------------------------------------------------------------
# Example:  goadmin
# Each finding line is a bare username (adminCount=1 accounts).

_OPT_ADMIN_COUNT_RE = re.compile(r"^(?P<username>\S+)\s*$")


def extract_opt_admin_count_admin_usernames(
    finding_lines: List[Tuple[str, str, str]],
    ip_to_asset_id_map: Dict,
) -> List[Dict]:
    """Extract admin usernames from ``--admin-count`` option output.

    Line format::
        goadmin
        ansible
    """
    results: List[Dict] = []
    for ip, hostname, rest in finding_lines:
        m = _OPT_ADMIN_COUNT_RE.match(rest)
        if not m:
            continue
        finding: Dict = {
            "username": m.group("username"),
            "host": ip,
            "hostname": hostname,
            "source_line": rest,
        }
        asset_id = ip_to_asset_id_map.get(ip, "")
        if asset_id:
            finding["asset_id"] = asset_id
        results.append(finding)
    return results


# ===================================================================
# Per-contract GROUP extractors
# ===================================================================


# -------------------------------------------------------------------
# Option: local_groups (smb --local-groups)
# -------------------------------------------------------------------
# Example:  546 - Guests

_OPT_LOCAL_GROUPS_RE = re.compile(
    r"^(?P<rid>\d+)\s+-\s+(?P<group_name>.+?)\s*$"
)


def extract_opt_local_groups_groups(
    finding_lines: List[Tuple[str, str, str]],
    ip_to_asset_id_map: Dict,
) -> List[Dict]:
    """Extract groups from ``--local-groups`` option output.

    Line format::
        546 - Guests
        544 - Administrators
    """
    results: List[Dict] = []
    for ip, hostname, rest in finding_lines:
        m = _OPT_LOCAL_GROUPS_RE.match(rest)
        if not m:
            continue
        finding: Dict = {
            "group_name": m.group("group_name"),
            "rid": m.group("rid"),
            "host": ip,
            "hostname": hostname,
            "source_line": rest,
        }
        asset_id = ip_to_asset_id_map.get(ip, "")
        if asset_id:
            finding["asset_id"] = asset_id
        results.append(finding)
    return results


# -------------------------------------------------------------------
# Option: groups (ldap --groups)
# -------------------------------------------------------------------
# Example:  Domain Admins                            membercount: 3

_OPT_GROUPS_RE = re.compile(
    r"^(?P<group_name>.+?)\s+membercount:\s*(?P<member_count>\d+)\s*$"
)


def extract_opt_groups_groups(
    finding_lines: List[Tuple[str, str, str]],
    ip_to_asset_id_map: Dict,
) -> List[Dict]:
    """Extract groups from ``--groups`` option output.

    Line format::
        Domain Admins                            membercount: 3
        Stark                                    membercount: 9
    """
    results: List[Dict] = []
    for ip, hostname, rest in finding_lines:
        m = _OPT_GROUPS_RE.match(rest)
        if not m:
            continue
        finding: Dict = {
            "group_name": m.group("group_name"),
            "member_count": int(m.group("member_count")),
            "host": ip,
            "hostname": hostname,
            "source_line": rest,
        }
        asset_id = ip_to_asset_id_map.get(ip, "")
        if asset_id:
            finding["asset_id"] = asset_id
        results.append(finding)
    return results


# ===================================================================
# Per-contract COMPUTER extractors
# ===================================================================


# -------------------------------------------------------------------
# Option: computers (ldap --computers)
# -------------------------------------------------------------------
# Example:  WINTERFELL$

_OPT_COMPUTERS_RE = re.compile(r"^(?P<computer_name>\S+)\s*$")


def extract_opt_computers_computers(
    finding_lines: List[Tuple[str, str, str]],
    ip_to_asset_id_map: Dict,
) -> List[Dict]:
    """Extract computer accounts from ``--computers`` option output.

    Line format::
        WINTERFELL$
        CASTELBLACK$
    """
    results: List[Dict] = []
    for ip, hostname, rest in finding_lines:
        m = _OPT_COMPUTERS_RE.match(rest)
        if not m:
            continue
        finding: Dict = {
            "computer_name": m.group("computer_name"),
            "host": ip,
            "hostname": hostname,
            "source_line": rest,
        }
        asset_id = ip_to_asset_id_map.get(ip, "")
        if asset_id:
            finding["asset_id"] = asset_id
        results.append(finding)
    return results


# ===================================================================
# Per-contract PASSWORD_POLICY extractors
# ===================================================================


# -------------------------------------------------------------------
# Option: pass_pol (smb --pass-pol)
# -------------------------------------------------------------------
# Example:  Minimum password length: 5

_OPT_PASS_POL_RE = re.compile(
    r"^(?P<key>[^:]+):\s*(?P<value>.+?)\s*$"
)


def extract_opt_pass_pol_password_policy(
    finding_lines: List[Tuple[str, str, str]],
    ip_to_asset_id_map: Dict,
) -> List[Dict]:
    """Extract password policy settings from ``--pass-pol`` option output.

    Line format::
        Minimum password length: 5
        Account Lockout Threshold: 5
        Domain Password Complex: 0
    """
    results: List[Dict] = []
    for ip, hostname, rest in finding_lines:
        m = _OPT_PASS_POL_RE.match(rest)
        if not m:
            continue
        finding: Dict = {
            "key": m.group("key").strip(),
            "value": m.group("value"),
            "host": ip,
            "hostname": hostname,
            "source_line": rest,
        }
        asset_id = ip_to_asset_id_map.get(ip, "")
        if asset_id:
            finding["asset_id"] = asset_id
        results.append(finding)
    return results


# ===================================================================
# Per-contract DELEGATION extractors
# ===================================================================


# -------------------------------------------------------------------
# Option: trusted_for_delegation (ldap --trusted-for-delegation)
# -------------------------------------------------------------------
# Example:  WINTERFELL$

_OPT_TRUSTED_DELEG_RE = re.compile(r"^(?P<account>\S+)\s*$")


def extract_opt_trusted_for_delegation_delegations(
    finding_lines: List[Tuple[str, str, str]],
    ip_to_asset_id_map: Dict,
) -> List[Dict]:
    """Extract delegation info from ``--trusted-for-delegation`` output.

    Line format::
        WINTERFELL$
    """
    results: List[Dict] = []
    for ip, hostname, rest in finding_lines:
        m = _OPT_TRUSTED_DELEG_RE.match(rest)
        if not m:
            continue
        finding: Dict = {
            "account": m.group("account"),
            "delegation_type": "Unconstrained",
            "host": ip,
            "hostname": hostname,
            "source_line": rest,
        }
        asset_id = ip_to_asset_id_map.get(ip, "")
        if asset_id:
            finding["asset_id"] = asset_id
        results.append(finding)
    return results


# -------------------------------------------------------------------
# Option: find_delegation (ldap --find-delegation)
# -------------------------------------------------------------------
# Example:  jon.snow     Person      Constrained w/ Protocol Transition CIFS/winterfell, CIFS/winterfell.north...

_OPT_FIND_DELEG_RE = re.compile(
    r"^(?P<account>\S+)\s+(?P<account_type>\S+)\s+"
    r"(?P<delegation_type>"
    r"Constrained w/ Protocol Transition"
    r"|Resource-Based Constrained"
    r"|Constrained"
    r"|Unconstrained"
    r")\s+"
    r"(?P<rights_to>.+?)\s*$"
)


def extract_opt_find_delegation_delegations(
    finding_lines: List[Tuple[str, str, str]],
    ip_to_asset_id_map: Dict,
) -> List[Dict]:
    """Extract delegation info from ``--find-delegation`` output.

    Line format::
        jon.snow     Person      Constrained w/ Protocol Transition CIFS/winterfell, ...
        CASTELBLACK$ Computer    Constrained                        HTTP/winterfell, ...
    """
    results: List[Dict] = []
    for ip, hostname, rest in finding_lines:
        m = _OPT_FIND_DELEG_RE.match(rest)
        if not m:
            continue
        finding: Dict = {
            "account": m.group("account"),
            "delegation_type": m.group("delegation_type").strip(),
            "rights_to": m.group("rights_to").strip(),
            "host": ip,
            "hostname": hostname,
            "source_line": rest,
        }
        asset_id = ip_to_asset_id_map.get(ip, "")
        if asset_id:
            finding["asset_id"] = asset_id
        results.append(finding)
    return results


# ===================================================================
# Per-contract SID extractors
# ===================================================================


# -------------------------------------------------------------------
# Option: get_sid (ldap --get-sid)
# -------------------------------------------------------------------
# Example:  Domain SID S-1-5-21-3455315044-2247855524-2949207569

_OPT_GET_SID_RE = re.compile(
    r"^Domain SID\s+(?P<sid>S-\d+-\d+-\d+(?:-\d+)+)\s*$"
)


def extract_opt_get_sid_sids(
    finding_lines: List[Tuple[str, str, str]],
    ip_to_asset_id_map: Dict,
) -> List[Dict]:
    """Extract domain SID from ``--get-sid`` option output.

    Line format::
        Domain SID S-1-5-21-3455315044-2247855524-2949207569
    """
    results: List[Dict] = []
    for ip, hostname, rest in finding_lines:
        m = _OPT_GET_SID_RE.match(rest)
        if not m:
            continue
        finding: Dict = {
            "sid": m.group("sid"),
            "host": ip,
            "hostname": hostname,
            "source_line": rest,
        }
        asset_id = ip_to_asset_id_map.get(ip, "")
        if asset_id:
            finding["asset_id"] = asset_id
        results.append(finding)
    return results


# ===================================================================
# Per-contract ACCOUNT_PW_NOT_REQUIRED extractors
# ===================================================================


# -------------------------------------------------------------------
# Option: password_not_required (ldap --password-not-required)
# -------------------------------------------------------------------
# Example:  User: SEVENKINGDOMS$ Status: enabled

_OPT_PW_NOT_REQUIRED_RE = re.compile(
    r"^User:\s*(?P<account>\S+)\s+Status:\s*(?P<status>\S+)\s*$"
)


def extract_opt_password_not_required_accounts(
    finding_lines: List[Tuple[str, str, str]],
    ip_to_asset_id_map: Dict,
) -> List[Dict]:
    """Extract accounts with PASSWD_NOTREQD flag from ``--password-not-required``.

    Line format::
        User: SEVENKINGDOMS$ Status: enabled
        User: Guest Status: disabled
    """
    results: List[Dict] = []
    for ip, hostname, rest in finding_lines:
        m = _OPT_PW_NOT_REQUIRED_RE.match(rest)
        if not m:
            continue
        finding: Dict = {
            "account": m.group("account"),
            "status": m.group("status"),
            "host": ip,
            "hostname": hostname,
            "source_line": rest,
        }
        asset_id = ip_to_asset_id_map.get(ip, "")
        if asset_id:
            finding["asset_id"] = asset_id
        results.append(finding)
    return results


# ===================================================================
# Per-contract ASREPROASTABLE extractors (reuses existing regex/function)
# ===================================================================
# extract_opt_asreproast_accounts defined above


# ===================================================================
# Per-contract KERBEROASTABLE extractors (reuses existing regex/function)
# ===================================================================
# extract_opt_kerberoasting_accounts defined above


# ===================================================================
# Per-contract VULNERABILITY extractors
# ===================================================================


# -------------------------------------------------------------------
# Module: spooler (smb -M spooler)
# -------------------------------------------------------------------
# Example:  Spooler service enabled

_MOD_SPOOLER_RE = re.compile(
    r"^(?P<details>Spooler service (?P<status>enabled|disabled))\s*$"
)


def extract_mod_spooler_vulnerabilities(
    finding_lines: List[Tuple[str, str, str]],
    ip_to_asset_id_map: Dict,
) -> List[Dict]:
    """Extract vulnerability info from ``spooler`` module output.

    Line format::
        Spooler service enabled
    """
    results: List[Dict] = []
    for ip, hostname, rest in finding_lines:
        m = _MOD_SPOOLER_RE.match(rest)
        if not m:
            continue
        if m.group("status") != "enabled":
            continue
        finding: Dict = {
            "name": "Spooler",
            "status": "VULNERABLE",
            "details": m.group("details"),
            "host": ip,
            "hostname": hostname,
            "source_line": rest,
        }
        asset_id = ip_to_asset_id_map.get(ip, "")
        if asset_id:
            finding["asset_id"] = asset_id
        results.append(finding)
    return results


# -------------------------------------------------------------------
# Module: coerce_plus (smb -M coerce_plus)
# -------------------------------------------------------------------
# Example:  VULNERABLE, PrinterBug

_MOD_COERCE_PLUS_RE = re.compile(
    r"^(?P<status>VULNERABLE|NOT VULNERABLE),?\s*(?P<details>.*)$"
)


def extract_mod_coerce_plus_vulnerabilities(
    finding_lines: List[Tuple[str, str, str]],
    ip_to_asset_id_map: Dict,
) -> List[Dict]:
    """Extract vulnerability info from ``coerce_plus`` module output.

    Line format::
        VULNERABLE, PrinterBug
    """
    results: List[Dict] = []
    for ip, hostname, rest in finding_lines:
        m = _MOD_COERCE_PLUS_RE.match(rest)
        if not m:
            continue
        if m.group("status") != "VULNERABLE":
            continue
        finding: Dict = {
            "name": m.group("details").strip() if m.group("details").strip() else "coerce_plus",
            "status": "VULNERABLE",
            "details": rest,
            "host": ip,
            "hostname": hostname,
            "source_line": rest,
        }
        asset_id = ip_to_asset_id_map.get(ip, "")
        if asset_id:
            finding["asset_id"] = asset_id
        results.append(finding)
    return results


# -------------------------------------------------------------------
# Module: ldap_checker (ldap -M ldap-checker)
# -------------------------------------------------------------------
# Example:  LDAP signing NOT enforced
# Example:  LDAPS channel binding is set to: Never

_MOD_LDAP_CHECKER_SIGNING_RE = re.compile(
    r"^LDAP signing (?P<status>NOT enforced|enforced)\s*$"
)
_MOD_LDAP_CHECKER_BINDING_RE = re.compile(
    r"^LDAPS channel binding is set to:\s*(?P<value>\S+)\s*$"
)


def extract_mod_ldap_checker_vulnerabilities(
    finding_lines: List[Tuple[str, str, str]],
    ip_to_asset_id_map: Dict,
) -> List[Dict]:
    """Extract vulnerability info from ``ldap-checker`` module output.

    Line formats::
        LDAP signing NOT enforced
        LDAPS channel binding is set to: Never
    """
    results: List[Dict] = []
    for ip, hostname, rest in finding_lines:
        # LDAP signing
        m = _MOD_LDAP_CHECKER_SIGNING_RE.match(rest)
        if m:
            if m.group("status") == "NOT enforced":
                finding: Dict = {
                    "name": "LDAP Signing",
                    "status": "VULNERABLE",
                    "details": "LDAP signing NOT enforced",
                    "host": ip,
                    "hostname": hostname,
                    "source_line": rest,
                }
                asset_id = ip_to_asset_id_map.get(ip, "")
                if asset_id:
                    finding["asset_id"] = asset_id
                results.append(finding)
            continue

        # LDAPS channel binding
        m = _MOD_LDAP_CHECKER_BINDING_RE.match(rest)
        if m:
            value = m.group("value")
            if value.lower() == "never":
                finding = {
                    "name": "LDAPS Channel Binding",
                    "status": "VULNERABLE",
                    "details": f"LDAPS channel binding is set to: {value}",
                    "host": ip,
                    "hostname": hostname,
                    "source_line": rest,
                }
                asset_id = ip_to_asset_id_map.get(ip, "")
                if asset_id:
                    finding["asset_id"] = asset_id
                results.append(finding)
    return results


# ===================================================================
# Registry: (family, identifier) -> dedicated extractor function
# ===================================================================

_CREDENTIAL_EXTRACTORS = {
    # Options
    ("option", "users"):           extract_opt_users_credentials,
    ("option", "sam"):             extract_opt_sam_credentials,
    ("option", "lsa"):             extract_opt_lsa_credentials,
    ("option", "ntds"):            extract_opt_ntds_credentials,

    # Modules
    ("module", "get_desc_users"):       extract_mod_get_desc_users_credentials,
    ("module", "user_desc"):            extract_mod_user_desc_credentials,
    ("module", "dpapi_hash"):           extract_mod_dpapi_hash_credentials,
}

_USERNAME_EXTRACTORS = {
    ("option", "users"):           extract_opt_users_usernames,
    ("option", "active_users"):    extract_opt_active_users_usernames,
    ("option", "rid_brute"):       extract_opt_rid_brute_usernames,
    ("option", "loggedon_users"):  extract_opt_loggedon_users_usernames,
}

_SHARE_EXTRACTORS = {
    ("option", "shares"):          extract_opt_shares_shares,
}

_ADMIN_USERNAME_EXTRACTORS = {
    ("option", "admin_count"):     extract_opt_admin_count_admin_usernames,
}

_GROUP_EXTRACTORS = {
    ("option", "local_groups"):    extract_opt_local_groups_groups,
    ("option", "groups"):          extract_opt_groups_groups,
}

_COMPUTER_EXTRACTORS = {
    ("option", "computers"):       extract_opt_computers_computers,
}

_PASSWORD_POLICY_EXTRACTORS = {
    ("option", "pass_pol"):        extract_opt_pass_pol_password_policy,
}

_DELEGATION_EXTRACTORS = {
    ("option", "trusted_for_delegation"): extract_opt_trusted_for_delegation_delegations,
    ("option", "find_delegation"):        extract_opt_find_delegation_delegations,
}

_SID_EXTRACTORS = {
    ("option", "get_sid"):         extract_opt_get_sid_sids,
}

_ACCOUNT_PW_NOT_REQUIRED_EXTRACTORS = {
    ("option", "password_not_required"): extract_opt_password_not_required_accounts,
}

_ASREPROASTABLE_EXTRACTORS = {
    ("option", "asreproast"):      extract_opt_asreproast_accounts,
}

_KERBEROASTABLE_EXTRACTORS = {
    ("option", "kerberoasting"):   extract_opt_kerberoasting_accounts,
}

_VULNERABILITY_EXTRACTORS = {
    ("module", "spooler"):         extract_mod_spooler_vulnerabilities,
    ("module", "coerce_plus"):     extract_mod_coerce_plus_vulnerabilities,
    ("module", "ldap_checker"):    extract_mod_ldap_checker_vulnerabilities,
}


def get_credential_extractor(family: str, identifier: str):
    """Return the credential extractor for a (family, identifier) pair, or None."""
    return _CREDENTIAL_EXTRACTORS.get((family, identifier))


def get_username_extractor(family: str, identifier: str):
    """Return the username extractor for a (family, identifier) pair, or None."""
    return _USERNAME_EXTRACTORS.get((family, identifier))


def get_share_extractor(family: str, identifier: str):
    """Return the share extractor for a (family, identifier) pair, or None."""
    return _SHARE_EXTRACTORS.get((family, identifier))


def get_admin_username_extractor(family: str, identifier: str):
    """Return the admin_username extractor for a (family, identifier) pair, or None."""
    return _ADMIN_USERNAME_EXTRACTORS.get((family, identifier))


def get_group_extractor(family: str, identifier: str):
    """Return the group extractor for a (family, identifier) pair, or None."""
    return _GROUP_EXTRACTORS.get((family, identifier))


def get_computer_extractor(family: str, identifier: str):
    """Return the computer extractor for a (family, identifier) pair, or None."""
    return _COMPUTER_EXTRACTORS.get((family, identifier))


def get_password_policy_extractor(family: str, identifier: str):
    """Return the password_policy extractor for a (family, identifier) pair, or None."""
    return _PASSWORD_POLICY_EXTRACTORS.get((family, identifier))


def get_delegation_extractor(family: str, identifier: str):
    """Return the delegation extractor for a (family, identifier) pair, or None."""
    return _DELEGATION_EXTRACTORS.get((family, identifier))


def get_sid_extractor(family: str, identifier: str):
    """Return the sid extractor for a (family, identifier) pair, or None."""
    return _SID_EXTRACTORS.get((family, identifier))


def get_vulnerability_extractor(family: str, identifier: str):
    """Return the vulnerability extractor for a (family, identifier) pair, or None."""
    return _VULNERABILITY_EXTRACTORS.get((family, identifier))


def get_account_pw_not_required_extractor(family: str, identifier: str):
    """Return the account_pw_not_required extractor for a (family, identifier) pair, or None."""
    return _ACCOUNT_PW_NOT_REQUIRED_EXTRACTORS.get((family, identifier))


def get_asreproastable_extractor(family: str, identifier: str):
    """Return the asreproastable_account extractor for a (family, identifier) pair, or None."""
    return _ASREPROASTABLE_EXTRACTORS.get((family, identifier))


def get_kerberoastable_extractor(family: str, identifier: str):
    """Return the kerberoastable_account extractor for a (family, identifier) pair, or None."""
    return _KERBEROASTABLE_EXTRACTORS.get((family, identifier))
