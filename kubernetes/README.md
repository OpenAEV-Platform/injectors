# OpenAEV Kubernetes Injector

Emulates Kubernetes and container attack techniques using
[Stratus Red Team](https://stratus-red-team.cloud/). Shares the
`StratusExecutor` helper with the Azure and GCP injectors.

## How it works

- A contract carries the target cluster kubeconfig; the injector writes it to a
  temp file, points `KUBECONFIG` at it, and detonates the selected Stratus
  technique with `--cleanup`.
- SUCCESS/ERROR is reported to the platform; DETECTION/PREVENTION expectations
  are scored by the relevant runtime detection collectors.

## Credentials

The kubeconfig is provided per inject through the contract field, written to a
temp file only for the detonation and removed afterwards - never persisted in
`config.yml`/`.env` and never logged.

## Development

```bash
poetry install
poetry run python -m unittest
```

## Icon

`kubernetes_injector/img/icon-kubernetes.png` must follow the injector icon
standard (square 1:1, 512x512 PNG, solid opaque background, genuine Kubernetes
artwork) - see OpenAEV-Platform/injectors#305.
