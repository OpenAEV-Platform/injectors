# injectors-sdk: agent instructions

Applies to work under `libs/injectors-sdk/`. Paths below are relative to that directory,
except in the commands, which run from the repository root.

injectors-sdk is the injector runtime (`OpenAEVInjectorHelper`, `OpenAEVConfigHelper`,
`ListenQueue`, `create_mq_ssl_context`). It builds on xtm-oaev-sdk, which lives in the
`client-python` repository, and `pyoaev` serves its names to legacy injectors through
deprecation shims.

## Hard rules

1. Use xtm-oaev-sdk through its package root only (`from xtm_oaev_sdk import X`). NEVER
   import `xtm_oaev_sdk._core`, `xtm_oaev_sdk.seam` or `xtm_oaev_sdk.public`.
2. NEVER import `pyoaev`, `collectors_sdk`, `thefuzz` or `requests`. The API client is
   injected (`api_client=`).
3. Respect the layering of `helpers`: `seam/` imports neither `public/` nor `_core/`,
   `_core/` NEVER imports `public/`, and `public/` imports `_core/` only to assign
   module-level defaults typed by their port. Every piece of behaviour goes through a seam
   port, one-liners included.
4. NEVER rename or remove a public name, constructor argument, attribute or overridable
   hook. Why: `pyoaev` serves these exact objects to legacy injectors, and its adapter
   overrides `OpenAEVInjectorHelper._create_default_api_client`.
5. `ListenQueue` stays a `threading.Thread` that keeps its public attributes. Its RabbitMQ
   loop runs in the core against `QueueListenerProtocol`: a new piece of listener state
   goes in that protocol first, and the adapter methods stay one-line delegations.
6. A seam change bumps the `helpers` `SEAM_VERSION` and gets an entry in `CHANGELOG.md`.

## Scope

Only make the changes directly requested. Do not add capabilities, abstractions, files,
dependencies or refactors beyond the task. A change that needs something new in
xtm-oaev-sdk belongs to `client-python`: stop and say so instead of working around it here.

## Stop and ask before

- changing a seam contract or the `SEAM_VERSION`;
- renaming or removing any public name;
- adding or changing a dependency in `pyproject.toml`;
- deleting any file.

## Done when

Run from the repository root, and report the real output:

```bash
(cd libs/injectors-sdk && python -m pytest test)
black --check libs/injectors-sdk
isort --profile black --check libs/injectors-sdk
flake8 --ignore=E,W libs/injectors-sdk
```

All four pass. NEVER run the linters from inside `libs/injectors-sdk/`: from there,
isort classifies `injectors_sdk` as first-party and reorders imports the repository keeps
as they are. Run the tools directly: the repository's pre-commit configuration cannot
install its pinned isort 5.10.1, and its isort hook says `arts:` instead of `args:`. The
repository CI does not run these tests, so this run is the only check. NEVER report a
check as passing without running it.

## Conventions

- Tests live in `test/`, exercise behaviour through the public API, and are written as
  `_given_*` / `_when_*` / `_then_*` helpers with a one-line `"""It ..."""` docstring.
- Recording a decision: add `docs/tdr/<slug>.tdr.md` with the header of an existing
  record and `status: draft`, plus a row in `docs/tdr/TDR_ToC.md`.
- Commit messages, when asked for: gitmoji + Conventional Commits with the
  `injectors-sdk` scope.

## Read when relevant

- `CONTRIBUTING.md`: setup, checks, and what differs from xtm-oaev-sdk.
- `docs/tdr/TDR_ToC.md`: the decisions behind the rules above.
- The xtm-oaev-sdk layering guide, `libs/xtm-oaev-sdk/docs/seam_strategy.md` in `client-python`.
