"""Injector dev runtime: runs an injector on one inject message, without the platform.

The message is read as the platform publishes it, completed the way the platform fills
it, and checked the way the platform checks it before anything runs. The injector then
gets it through its usual callback, against a stand-in of the platform client that
writes every call to the dev sink. The run ends on the inject's ``complete`` callback,
or after ``--timeout`` seconds without one.
"""

import json
import sys
from types import SimpleNamespace
from typing import Any, Callable

from injectors_sdk.seam.runtime import InjectorDevOptions
from pydantic import ValidationError
from xtm_oaev_sdk import (
    ContractValidator,
    ExecutableInject,
    dev_sink,
    environment_secret_values,
)

from .client import DevPlatformClient
from .message import complete_message, contract_fields
from .options import injector_help, injector_options

__all__ = ["InjectorDevRuntime"]

#: Statuses of the platform's failure family: a run completed with one exits 1.
FAILED_STATUSES = frozenset(
    {
        "ERROR",
        "COMMAND_NOT_FOUND",
        "COMMAND_CANNOT_BE_EXECUTED",
        "PREREQUISITE_FAILED",
        "INVALID_USAGE",
        "TIMEOUT",
        "INTERRUPTED",
    }
)
#: Body keys holding ids, enum values or numbers: a secret never rewrites them.
KEPT_KEYS = (
    "tracking_total_count",
    "execution_status",
    "execution_duration",
    "execution_action",
    "execution_context_identifiers",
    "injector_id",
    "injector_type",
)


def _contracts(injector_config: dict[str, Any]) -> list[dict[str, Any]]:
    contracts = injector_config.get("injector_contracts") or []
    if isinstance(contracts, dict):
        contracts = contracts.get("data") or []
    return [c for c in contracts if isinstance(c, dict)]


def _elements(contract: dict[str, Any]) -> list[Any]:
    return [
        SimpleNamespace(
            key=f.get("key"),
            type=f.get("type"),
            mandatory=bool(f.get("mandatory")),
            mandatoryGroups=f.get("mandatoryGroups") or [],
            mandatoryConditionFields=f.get("mandatoryConditionFields") or [],
            mandatoryConditionValues=f.get("mandatoryConditionValues") or {},
            defaultValue=f.get("defaultValue"),
            cardinality=f.get("cardinality"),
            choices=f.get("choices"),
        )
        for f in contract_fields(contract)
    ]


def _provided(elements: list[Any], message: ExecutableInject) -> dict[str, list[str]]:
    """The fields the inject carries apart from its content, with their ids, the way
    the platform counts them: targets, teams and credential references."""
    injection = message.injection.model_extra or {}
    teams = [str(team) for team in injection.get("inject_teams") or []]
    ids = {
        "asset": [asset.asset_id for asset in message.assets],
        "asset-group": [group.asset_group_id for group in message.assetGroups],
        "team": teams or (["all"] if injection.get("inject_all_teams") else []),
        "credential-reference": [
            str(ref) for ref in injection.get("inject_secret_references") or []
        ],
    }
    return {e.key: ids[e.type] for e in elements if ids.get(e.type)}


def _read(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def _completes(calls: list[dict[str, Any]], inject_id: str) -> list[dict[str, Any]]:
    path = f"/api/injects/execution/callback/{inject_id}"
    return [
        call["body"]
        for call in calls
        if call["path"] == path
        and isinstance(call["body"], dict)
        and call["body"].get("execution_action") == "complete"
    ]


class InjectorDevRuntime:
    """Implements ``InjectorDevRuntimePort``."""

    def options(self, argv: list[str] | None = None) -> InjectorDevOptions:
        return injector_options(argv)

    def help(self) -> str:
        return injector_help()

    def exit_on_help(self, options: InjectorDevOptions) -> None:
        if options.help:
            sys.stdout.write(self.help())
            sys.stdout.flush()
            raise SystemExit(0)

    def api_client(self, config: Any, options: InjectorDevOptions) -> DevPlatformClient:
        secrets = environment_secret_values()
        configuration = config.get_config_obj() if config is not None else None
        if configuration is not None:
            secrets += configuration.secret_values()
        return DevPlatformClient(dev_sink(options.out, secrets, KEPT_KEYS))

    def run(
        self,
        api: Any,
        injector_config: dict[str, Any],
        callback: Callable[[dict[str, Any]], None],
        logger: Any,
        options: InjectorDevOptions,
    ) -> int:
        sink = api.sink
        try:
            return self._run(sink, injector_config, callback, logger, options)
        finally:
            sink.close()

    def _run(
        self,
        sink: Any,
        injector_config: dict[str, Any],
        callback: Callable[[dict[str, Any]], None],
        logger: Any,
        options: InjectorDevOptions,
    ) -> int:
        if not options.inject:
            return sink.refuse("--inject PATH (or - for stdin) is required in dev mode")
        try:
            document = json.loads(_read(options.inject))
        except (OSError, ValueError) as error:
            return sink.refuse(f"not a platform inject message: {error}")
        injection = document.get("injection") if isinstance(document, dict) else None
        if not isinstance(injection, dict):
            return sink.refuse("not a platform inject message: it has no injection")
        reference = injection.get("inject_injector_contract")
        contract_id = (
            reference.get("injector_contract_id")
            if isinstance(reference, dict)
            else None
        )
        if not contract_id:
            return sink.refuse(
                "not a platform inject message: it names no injector contract"
            )
        contract = next(
            (
                c
                for c in _contracts(injector_config)
                if c.get("contract_id") == contract_id
            ),
            None,
        )
        if contract is None:
            return sink.refuse(f"contract {contract_id} is not served by this injector")
        document = complete_message(document, contract)
        try:
            message = ExecutableInject.model_validate(document)
        except ValidationError as error:
            return sink.refuse(f"not a platform inject message: {error}")
        elements = _elements(contract)
        violations = ContractValidator().validate(
            elements,
            message.injection.inject_content or {},
            _provided(elements, message),
        )
        if violations:
            return sink.refuse(
                "inject content fails its contract: "
                + "; ".join(v.message for v in violations)
            )
        inject_id = message.injection.inject_id
        logger.info(f"Dev mode: running inject {inject_id} from {options.inject}")
        callback(document)
        if not sink.wait_for(
            lambda calls: bool(_completes(calls, inject_id)), options.timeout
        ):
            sink.note(
                f"no complete callback for inject {inject_id} within"
                f" {options.timeout:g} seconds"
            )
            return 1
        failed = any(
            str(body.get("execution_status")).upper() in FAILED_STATUSES
            for body in _completes(sink.calls, inject_id)
        )
        return 1 if failed else 0
