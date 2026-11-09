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
