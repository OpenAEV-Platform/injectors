"""Build ContractOutputElement lists based on output registry types."""

from typing import List, Set

from pyoaev.contracts import ContractBuilder
from pyoaev.contracts.contract_config import ContractOutputElement, ContractOutputType

from netexec.contracts.output_registry import (
    ACCOUNT_PW_NOT_REQUIRED,
    ADMIN_USERNAME,
    ASREPROASTABLE,
    COMPUTER,
    CREDENTIALS,
    DELEGATION,
    GROUP,
    KERBEROASTABLE,
    PASSWORD_POLICY,
    SHARE,
    SID,
    TEXT,
    USERNAME,
    VULNERABILITY,
)

# ---------------------------------------------------------------------------
# One ContractOutputElement per output type
# ---------------------------------------------------------------------------

_TEXT_OUTPUT = ContractOutputElement(
    type=ContractOutputType.Text,
    field="text",
    isMultiple=True,
    isFindingCompatible=True,
    labels=["netexec"],
)

_CREDENTIALS_OUTPUT = ContractOutputElement(
    type=ContractOutputType.Credentials,
    field="credentials",
    isMultiple=True,
    isFindingCompatible=True,
    labels=["netexec"],
)

_USERNAME_OUTPUT = ContractOutputElement(
    type=ContractOutputType.Username,
    field="usernames",
    isMultiple=True,
    isFindingCompatible=True,
    labels=["netexec"],
)

_SHARE_OUTPUT = ContractOutputElement(
    type=ContractOutputType.Share,
    field="shares",
    isMultiple=True,
    isFindingCompatible=True,
    labels=["netexec"],
)

_ADMIN_USERNAME_OUTPUT = ContractOutputElement(
    type=ContractOutputType.AdminUsername,
    field="admin_usernames",
    isMultiple=True,
    isFindingCompatible=True,
    labels=["netexec"],
)

_GROUP_OUTPUT = ContractOutputElement(
    type=ContractOutputType.Group,
    field="groups",
    isMultiple=True,
    isFindingCompatible=True,
    labels=["netexec"],
)

_COMPUTER_OUTPUT = ContractOutputElement(
    type=ContractOutputType.Computer,
    field="computers",
    isMultiple=True,
    isFindingCompatible=True,
    labels=["netexec"],
)

_PASSWORD_POLICY_OUTPUT = ContractOutputElement(
    type=ContractOutputType.PasswordPolicy,
    field="password_policy",
    isMultiple=True,
    isFindingCompatible=True,
    labels=["netexec"],
)

_DELEGATION_OUTPUT = ContractOutputElement(
    type=ContractOutputType.Delegation,
    field="delegations",
    isMultiple=True,
    isFindingCompatible=True,
    labels=["netexec"],
)

_SID_OUTPUT = ContractOutputElement(
    type=ContractOutputType.Sid,
    field="sids",
    isMultiple=True,
    isFindingCompatible=True,
    labels=["netexec"],
)

_VULNERABILITY_OUTPUT = ContractOutputElement(
    type=ContractOutputType.Vulnerability,
    field="vulnerabilities",
    isMultiple=True,
    isFindingCompatible=True,
    labels=["netexec"],
)

_ACCOUNT_PW_NOT_REQUIRED_OUTPUT = ContractOutputElement(
    type=ContractOutputType.AccountWithPasswordNotRequired,
    field="accounts_pw_not_required",
    isMultiple=True,
    isFindingCompatible=True,
    labels=["netexec"],
)

_ASREPROASTABLE_OUTPUT = ContractOutputElement(
    type=ContractOutputType.AsreproastableAccount,
    field="asreproastable_accounts",
    isMultiple=True,
    isFindingCompatible=True,
    labels=["netexec"],
)

_KERBEROASTABLE_OUTPUT = ContractOutputElement(
    type=ContractOutputType.KerberoastableAccount,
    field="kerberoastable_accounts",
    isMultiple=True,
    isFindingCompatible=True,
    labels=["netexec"],
)

_TYPE_TO_ELEMENT = {
    TEXT: _TEXT_OUTPUT,
    CREDENTIALS: _CREDENTIALS_OUTPUT,
    USERNAME: _USERNAME_OUTPUT,
    SHARE: _SHARE_OUTPUT,
    ADMIN_USERNAME: _ADMIN_USERNAME_OUTPUT,
    GROUP: _GROUP_OUTPUT,
    COMPUTER: _COMPUTER_OUTPUT,
    PASSWORD_POLICY: _PASSWORD_POLICY_OUTPUT,
    DELEGATION: _DELEGATION_OUTPUT,
    SID: _SID_OUTPUT,
    VULNERABILITY: _VULNERABILITY_OUTPUT,
    ACCOUNT_PW_NOT_REQUIRED: _ACCOUNT_PW_NOT_REQUIRED_OUTPUT,
    ASREPROASTABLE: _ASREPROASTABLE_OUTPUT,
    KERBEROASTABLE: _KERBEROASTABLE_OUTPUT,
}


def build_outputs_for_types(output_types: Set[str]) -> List[ContractOutputElement]:
    """Return the built output list for a given set of output type keys."""
    if not output_types:
        return []
    elements = [_TYPE_TO_ELEMENT[t] for t in sorted(output_types) if t in _TYPE_TO_ELEMENT]
    if not elements:
        return []
    return ContractBuilder().add_outputs(elements).build_outputs()
