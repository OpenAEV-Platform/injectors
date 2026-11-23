# Changelog

Every notable change to injectors-sdk lands here. Every seam change too, with the new
version of its seam.

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
