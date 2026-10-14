"""Cloud authentication evidence read from the Prowler console output.

Once its provider is set up, which includes authenticating against the cloud
(``sts:GetCallerIdentity`` for AWS), Prowler 5.36 prints a credentials box on
stdout, unless ``--only-logs`` is set (``prowler/__main__.py``)::

    -> Using the AWS credentials below:
      · AWS-CLI Profile: default
      · AWS Account: 123456789012
      · Caller Identity ARN: arn:aws:iam::123456789012:user/prowler

Its presence proves the authentication succeeded. Only an allowlist of
identity facts is kept from it, each bounded and log-safe; nothing else from
the console output is read.
"""

import re
from dataclasses import dataclass

# Every key Prowler 5.36 prints in each provider box, used to split lines that
# carry several "Key: value" pairs (Azure). Only ``_KEPT_KEYS`` are retained.
_BOX_KEYS = {
    "AWS": (
        "AWS-CLI Profile",
        "AWS Regions",
        "AWS Account",
        "User Id",
        "Caller Identity ARN",
        "Assumed Role ARN",
    ),
    "Azure": (
        "Azure Tenant Domain",
        "Azure Tenant ID",
        "Azure Region",
        "Azure Subscriptions",
        "Azure Resource Groups",
        "Azure Identity Type",
        "Azure Identity ID",
    ),
    "GCP": (
        "GCP Account",
        "GCP Project IDs",
        "Profile",
        "Impersonated Service Account",
        "Excluded GCP Project IDs",
    ),
    "Kubernetes": (
        "Kubernetes Cluster",
        "User",
        "Namespaces",
        "Roles",
        "Kubernetes Pod",
        "Namespace",
    ),
}
_KEPT_KEYS = {
    "AWS": ("AWS Account", "Caller Identity ARN"),
    "Azure": ("Azure Tenant ID", "Azure Subscriptions", "Azure Identity Type"),
    "GCP": ("GCP Account", "GCP Project IDs"),
    "Kubernetes": ("Kubernetes Cluster", "User"),
}
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_BOX_TITLE = re.compile(r"^-> Using the (AWS|Azure|GCP|Kubernetes) credentials below:$")
_BOX_LINE_PREFIX = "· "
_MAXIMUM_SCANNED_LINES = 200
_MAXIMUM_VALUE_LENGTH = 256
_AWS_ACCOUNT_ID = re.compile(r"\d{12}")
# arn:<partition>:iam::<account>:role/<path/name>
_AWS_ROLE_ARN = re.compile(r"^arn:aws[a-z-]*:iam::(\d{12}):role/.+$")


@dataclass(frozen=True)
class CloudAuthentication:
    """The provider Prowler authenticated against and its allowlisted identity."""

    provider: str
    identity: tuple[tuple[str, str], ...]

    def value(self, key: str) -> str | None:
        """Return one identity fact by its Prowler label."""
        return dict(self.identity).get(key)

    @property
    def aws_account_id(self) -> str | None:
        """Return the authenticated AWS account, when it is a valid account ID."""
        account = self.value("AWS Account")
        if account is not None and _AWS_ACCOUNT_ID.fullmatch(account):
            return account
        return None


def parse_authentication(stdout: bytes) -> CloudAuthentication | None:
    """Return the credentials box of the Prowler output, if it was printed."""
    from prowler.injector.failure_taxonomy import _safe_text

    text = _ANSI_ESCAPE.sub("", stdout.decode("utf-8", errors="replace"))
    lines = text.splitlines()[:_MAXIMUM_SCANNED_LINES]
    for index, line in enumerate(lines):
        title = _BOX_TITLE.match(line.strip())
        if title is None:
            continue
        provider = title.group(1)
        pairs: dict[str, str] = {}
        for box_line in lines[index + 1 :]:
            stripped = box_line.strip()
            if not stripped.startswith(_BOX_LINE_PREFIX):
                break
            pairs.update(_split_pairs(provider, stripped[len(_BOX_LINE_PREFIX) :]))
        identity = tuple(
            (key, _safe_text(pairs[key][:_MAXIMUM_VALUE_LENGTH]))
            for key in _KEPT_KEYS[provider]
            if pairs.get(key)
        )
        return CloudAuthentication(provider, identity)
    return None


def _split_pairs(provider: str, line: str) -> dict[str, str]:
    """Split one box line into its "Key: value" pairs."""
    keys = "|".join(re.escape(key) for key in _BOX_KEYS[provider])
    matches = list(re.finditer(rf"(?:^|\s)({keys}): ", line))
    pairs: dict[str, str] = {}
    for position, match in enumerate(matches):
        end = matches[position + 1].start() if position + 1 < len(matches) else None
        pairs[match.group(1)] = line[match.end() : end].strip()
    return pairs


def aws_account_from_role_arn(role_arn: str) -> str | None:
    """Return the account of an IAM role ARN, the account the role lives in."""
    match = _AWS_ROLE_ARN.fullmatch(role_arn)
    return match.group(1) if match else None


class AwsAccountMismatchError(ValueError):
    """The credential reaches another AWS account than the inject declares.

    Only the reference id and the two 12-digit account IDs are kept; they are
    identifiers, never secret values.
    """

    def __init__(
        self, reference: str | None, expected_account: str, credential_account: str
    ) -> None:
        """Retain the safe identifiers of the mismatch."""
        self.reference = reference
        self.expected_account = expected_account
        self.credential_account = credential_account
        super().__init__("AWS account mismatch")


class CredentialScopeMissingError(ValueError):
    """The credential lacks the region, subscription, or project of the scan.

    With the credential manager, these come from the credential only. Only
    the reference id and the closed field keys are kept, never a value.
    """

    def __init__(self, reference: str | None, fields: tuple[str, ...]) -> None:
        """Retain the safe identifiers of the missing scope."""
        self.reference = reference
        self.fields = fields
        super().__init__("Credential scope missing")
