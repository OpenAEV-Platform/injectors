# Changelog

Every notable change to injectors-sdk lands here. Every seam change too, with the new
version of its seam.

## [Unreleased]

### Added

- `runtime` (new): the dev options of an injector. `InjectorDevOptions` (seam model)
  extends `xtm_oaev_sdk.DevOptions` with `--inject`, `--emit`, `--dump-contracts`,
  `--list-contracts` and `--new-inject`; `injector_dev_options(argv=None)` reads them
  and `injector_dev_help()` describes them next to the common options. They are read
  only under their full name; collector options and the injector's own flags are left
  alone. Port `InjectorDevRuntimePort`. Seam `runtime` `1.0.0`.
- `helpers`: started with `--dev --help` (or `-h`), `OpenAEVInjectorHelper` prints the
  injector dev options and exits with code 0, before building the API client or
  reaching the platform. Without `--dev`, `-h` stays the injector's own.
- `runtime`: run an injector without the platform. Started with `--dev`,
  `OpenAEVInjectorHelper` never builds the API client, registers against a local
  stand-in and starts no heartbeat; `listen` reads `--inject` (a file, or `-` for
  stdin) as the platform publishes it, completes a lean message the way the platform
  fills it (the injector's own contract under both id paths, an inject id derived
  from the message, so the same message writes the same calls at every run, a title,
  the content defaults under the content given), checks it the way the platform
  checks it (`xtm_oaev_sdk.ContractValidator`, the targets the message carries counted
  as set), hands it to the callback once, and writes every call to the dev sink, one
  JSON list (`--out`, or stdout). The run ends on the inject's `complete` callback, or
  after `--timeout` seconds (600 by default) without one. Exit codes: 0 completed, 1
  failed (a status of the platform's failure family) or never completed, 2 refused
  before running. A document download, a target search or any manager the stand-in
  does not offer raises `xtm_oaev_sdk.NeedsPlatformError` naming it. Secrets from the
  configuration and the environment are redacted. `InjectorDevOptions` gains
  `timeout`; the port gains `api_client` and `run`. Seam `runtime` `1.0.0`.
- `runtime`: the contract helpers of dev mode. `--list-contracts` lists the contracts
  the injector serves (id, label, target types); `--new-inject CONTRACT` (an id, or a
  piece of a label, whatever the case) writes on stdout a lean inject message to edit,
  prefilled the way the platform's inject form fills a new inject, its target type
  switched to one dev mode can run, with a guide to each field and what is still to
  fill on stderr; a name matching no contract or several is refused (exit code 2) with
  the candidates. `--dump-contracts` writes the registration (`POST /api/injectors`,
  contracts included) to the dev sink. Each exits with code 0.
- `runtime`: `--emit expectations` makes a dev run also write, on stdout, the pending
  expectations the platform would then serve to collectors: the JSON list a collector
  reads with `--expectations`, so an injector pipes into a collector. The signatures
  are read from the execution callbacks the injector posted, the way the platform's
  `SignatureOutputProcessor` reads them (target: agent, else asset, else asset group;
  DETECTION and PREVENTION only, those the inject content declares; fallback keys;
  scalar values with text, a type and value pair kept once), checked against the
  cases of the platform's `SignatureOutputProcessorTest`. Without `--out`, the calls go
  to stderr, so stdout carries the pending expectations alone; what the platform would
  have dropped is noted on stderr.
- `runtime`: `--record PATH` writes every outside call the injector makes during a dev
  run (its product's API over HTTP, its commands through `subprocess.run`) and the
  answers to a tape (`xtm_oaev_sdk.CallTape`, one readable JSON document whose header
  names the injector); `--replay PATH` answers them from it, offline, any other outbound
  connection failing. Secrets from the configuration and the environment stay off the
  tape. Both at once, or a tape that cannot be replayed, are refused (exit code 2).

## [0.1.0] - Unreleased

First version. The injector runtime of `pyoaev` 3.260923.0 moves out and into this
SDK. The former `pyoaev.helpers` names keep working, each one firing a
`DeprecationWarning`.

### Added

- `helpers`: `OpenAEVInjectorHelper`, `OpenAEVConfigHelper`, `ListenQueue`,
  `create_mq_ssl_context` (from `pyoaev.helpers`). Seam `1.0.0`.

### Changed (compared with pyoaev)

- `OpenAEVInjectorHelper` stops building the API client. Pass `api_client=` yourself.
- `requires-python` moves from `>=3.11` to `>=3.12`, like xtm-oaev-sdk it builds on.
