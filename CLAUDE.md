# OpenAEV injectors: agent instructions

Applies to the injectors in this repository (every directory except `libs/`). Work under
`libs/injectors-sdk/` follows `libs/injectors-sdk/CLAUDE.md` instead.

Build, lint and test commands and repository conventions are in
`.github/copilot-instructions.md` and `CONTRIBUTING.md`. Follow them. This file adds the
rules about `pyoaev` and the SDKs, and wins over them on that topic.

## Context: the SDK split

The shared runtime of `pyoaev` is moving into SDKs: `injectors-sdk` (`libs/` in this
repository) and `xtm-oaev-sdk` (in `client-python`). `pyoaev` keeps the OpenAEV API
client and serves the former names through deprecation shims. The `pyoaev` releases the
injectors pin today do NOT ship the SDKs.

## Hard rules

1. Keep the `pyoaev` imports an injector already uses (`pyoaev.helpers.OpenAEVInjectorHelper`,
   `pyoaev.contracts`, `pyoaev.configuration`…) as long as its pinned `pyoaev` does not
   depend on the SDKs. NEVER import `injectors_sdk` or `xtm_oaev_sdk` in such an
   injector. Why: outside the `dev` extra, the install takes the pinned `pyoaev` from
   PyPI, where the SDK packages do not exist, so the injector would fail at runtime.
2. To check, run `pip show pyoaev` in the injector's environment: the SDKs are usable
   only if `injectors-sdk` appears under `Requires`.
3. NEVER change a `pyoaev` version pin, a dependency marker, or add an SDK dependency
   without explicit approval.
4. NEVER edit `libs/injectors-sdk/` as a side effect of an injector task.

## Migrating an injector to the SDKs

Only when asked, and only once rule 2 passes:

- replace each legacy import with the one named by its `DeprecationWarning`, always
  from the package root (`from injectors_sdk import OpenAEVInjectorHelper`,
  `from xtm_oaev_sdk import ContractBuilder`), never from `public`, `seam` or `_core`;
- build the client yourself and pass it:
  `OpenAEVInjectorHelper(config, icon, api_client=OpenAEV(...))`;
- keep `pyoaev` for `OpenAEV` and the `pyoaev.apis` managers.

The full import table and before/after examples are in the
[migration guide](https://github.com/OpenAEV-Platform/client-python/blob/main/libs/xtm-oaev-sdk/docs/migration_guide.md).

## Stop and ask before

- changing any dependency declaration (`pyproject.toml`, requirements files);
- migrating an injector's imports to the SDKs;
- continuing when installing a local `client-python` fails to resolve `xtm-oaev-sdk`,
  `collectors-sdk` or `injectors-sdk`. Report the error instead of working around it.

## Done when

The linters and the injector's tests from `.github/copilot-instructions.md` pass. Report
the real output, and NEVER report a check as passing without running it.
