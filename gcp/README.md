# OpenAEV GCP Injector

Emulates Google Cloud Platform attack techniques using
[Stratus Red Team](https://stratus-red-team.cloud/). It builds on the reusable
`StratusExecutor` helper (`injector_common/stratus_executor.py`), which lives in
`injector_common` so other Stratus-based cloud injectors can adopt it later.

## How it works

- A contract carries the target GCP project id and a service account key (JSON);
  the injector materializes the key on disk, sets Application Default
  Credentials, and detonates the selected Stratus technique with `--cleanup`.
- SUCCESS/ERROR is reported to the platform; DETECTION/PREVENTION expectations
  are scored by the relevant cloud detection collectors.

## Credentials

The GCP service account key and project id are provided per inject through the
contract fields, written to a temp file only for the detonation and removed
afterwards - never persisted in `config.yml`/`.env` and never logged.

## Development

```bash
poetry install
poetry run python -m unittest
```

## Icon

`gcp_injector/img/icon-gcp.png` currently ships a neutral placeholder. The
genuine Google Cloud Platform artwork (square 1:1, 512x512 PNG, solid opaque
background) is tracked in OpenAEV-Platform/injectors#330, and must land before
the injector is marked verified.
