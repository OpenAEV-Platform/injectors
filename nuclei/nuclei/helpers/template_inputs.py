"""Collect the variables a template needs before Nuclei runs it.

A template that needs ``{{username}}``/``{{password}}`` or any other operator value
is never run without them: Nuclei would send the requests with empty values (an
empty-credential login on every target) and report a no-match that tests nothing.
The scan is refused with ``MissingTemplateInputs`` instead, which the injector
reports as not executed.
"""

import os
import shlex
from typing import Any, Dict, Iterable, List, Optional, Set

from pyoaev.credential import resolve_inject_credential
from pyoaev.credential.resolved import UsernamePasswordSecret
from pyoaev.credential.types import CredentialType

from nuclei.helpers.template_analysis import (
    CREDENTIAL_VARIABLES,
    TemplateAnalysis,
    is_secret_variable,
    templates_directory,
)
from nuclei.nuclei_contracts.external_contracts import template_variable_field

REDACTED = "***"


class MissingTemplateInputs(Exception):
    """The template needs values the inject does not carry: it is not run."""

    def __init__(self, missing: List[str]):
        self.missing = list(missing)
        credentials = [name for name in missing if name in CREDENTIAL_VARIABLES]
        others = [name for name in missing if name not in CREDENTIAL_VARIABLES]
        reasons = []
        if credentials:
            reasons.append(
                "missing credentials ({}): attach a username/password credential "
                "to the inject".format(", ".join(credentials))
            )
        if others:
            reasons.append(
                "missing template variables ({}): fill the matching "
                "'Template variable' fields".format(", ".join(others))
            )
        super().__init__(
            "Not executed, inconclusive: "
            + "; ".join(reasons)
            + ". The template cannot match without them, so no request was sent "
            "and no vulnerability verdict is given."
        )


class TemplateNotFound(Exception):
    """A template the inject names is not in the template set: it is not run.

    Nuclei skips an unknown -id or -t silently and reports no match, which reads
    "not vulnerable" while nothing was tested.
    """

    def __init__(self, missing: List[str]):
        self.missing = list(missing)
        super().__init__(
            "Not executed: template not found: {}. No request was sent and no "
            "vulnerability verdict is given for {}.".format(
                ", ".join(missing), "it" if len(missing) == 1 else "them"
            )
        )


_ID_FLAGS = ("-id", "-template-id")
_TEMPLATE_FLAGS = ("-t", "-templates")


def _flag_values(tokens: List[str], flags: Iterable[str]) -> List[str]:
    values: List[str] = []
    for index, token in enumerate(tokens):
        for flag in flags:
            if token == flag and index + 1 < len(tokens):
                values.extend(tokens[index + 1].split(","))
            elif token.startswith(flag + "="):
                values.extend(token[len(flag) + 1 :].split(","))
    return [value.strip() for value in values if value.strip()]


def _template_ids(directory: str) -> Set[str]:
    ids: Set[str] = set()
    for _, _, files in os.walk(directory):
        for name in files:
            if name.endswith((".yaml", ".yml")):
                ids.add(os.path.splitext(name)[0].lower())
    return ids


def check_templates_exist(
    content: Dict[str, Any], directory: Optional[str] = None
) -> None:
    """Raise TemplateNotFound for every template file or id the inject names
    (the template field, -t and -id in the options) that the template set does
    not hold. Skipped when the template set itself is absent."""
    if not isinstance(content, dict):
        return
    directory = directory or templates_directory()
    if not os.path.isdir(directory):
        return
    try:
        tokens = shlex.split(content.get("options") or "")
    except ValueError:
        tokens = []
    paths = _flag_values(tokens, _TEMPLATE_FLAGS)
    if content.get("template"):
        paths.append(str(content["template"]).strip())
    missing: List[str] = []
    for path in paths:
        if not path.endswith((".yaml", ".yml")):
            continue  # a directory or a workflow: Nuclei expands it itself
        candidate = path if os.path.isabs(path) else os.path.join(directory, path)
        if not os.path.isfile(candidate) and path not in missing:
            missing.append(path)
    ids = _flag_values(tokens, _ID_FLAGS)
    if ids:
        known = _template_ids(directory)
        for template_id in ids:
            if "*" in template_id:
                continue  # a glob Nuclei matches itself
            if template_id.lower() not in known and template_id not in missing:
                missing.append(template_id)
    if missing:
        raise TemplateNotFound(missing)


def collect_template_variables(
    analysis: Optional[TemplateAnalysis],
    content: Dict[str, Any],
    resolve_credentials,
) -> Dict[str, str]:
    """The ``-var`` values for a template, or MissingTemplateInputs.

    ``resolve_credentials`` is called only when the template needs credentials;
    it returns a ``UsernamePasswordSecret`` or None.
    """
    if analysis is None or not analysis.variables:
        return {}
    values: Dict[str, str] = {}
    if analysis.needs_credentials:
        secret = resolve_credentials()
        if isinstance(secret, UsernamePasswordSecret):
            if secret.username:
                values["username"] = secret.username
            if secret.password:
                values["password"] = secret.password
    for name in analysis.variables:
        if name in values:
            continue
        raw = content.get(template_variable_field(name)) if content else None
        if isinstance(raw, str) and raw.strip():
            values[name] = raw.strip()
    missing = [name for name in analysis.variables if name not in values]
    if missing:
        raise MissingTemplateInputs(missing)
    return values


def credential_resolver(api, inject_id: str, data: Dict[str, Any]):
    """Resolve the identity credential attached to the inject, just in time."""

    def resolve():
        return resolve_inject_credential(api, inject_id, data, CredentialType.IDENTITY)

    return resolve


def variable_args(values: Dict[str, str]) -> List[str]:
    args: List[str] = []
    for name, value in values.items():
        args += ["-var", "{}={}".format(name, value)]
    return args


def redact_args(args: List[str]) -> List[str]:
    """The command line with secret -var values hidden, for logs and traces."""
    redacted = list(args)
    for index, arg in enumerate(redacted[:-1]):
        if arg in ("-var", "-V") and "=" in redacted[index + 1]:
            name, _ = redacted[index + 1].split("=", 1)
            if is_secret_variable(name):
                redacted[index + 1] = "{}={}".format(name, REDACTED)
    return redacted
