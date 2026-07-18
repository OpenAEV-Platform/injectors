# OpenAEV Stratus Red Team Injector

Emulates granular cloud and container adversary techniques using
[Stratus Red Team](https://stratus-red-team.cloud/). A single injector exposes
**one contract per Stratus technique**, so attack scenarios are organized by
capability (each specific TTP is a directly selectable inject) rather than split
across one injector per cloud.

## Contracts

- One contract per Stratus technique (99 in the pinned release), each tagged
  with its MITRE ATT&CK technique ids where Stratus declares them. The technique
  is fixed by the contract; the operator only provides the platform credentials.
- One "Detonate a custom Stratus technique" contract per platform, which takes a
  free-form technique id so any technique in the pinned Stratus release can be
  run even before a dedicated contract exists.

The technique catalog in `stratus/contracts/techniques.py` is generated from the
Stratus Red Team source (`internal/attacktechniques`).

## Supported platforms

Each technique belongs to one platform, which determines the credentials:

| Platform | Credentials |
|---|---|
| AWS | Access key id / secret, optional session token, region |
| Azure | Tenant / subscription / client id / client secret |
| Entra ID | Tenant / client id / client secret |
| Google Cloud Platform | Project id + service account key (JSON) |
| Kubernetes | Kubeconfig (YAML) |
| Amazon EKS | AWS access key id / secret, optional session token, region |

## How it works

- The injector resolves the target platform and technique from the contract id
  (fixed-technique contracts) or from the inject content (custom contracts),
  builds the Stratus process environment, and detonates the technique with
  `--cleanup` so no live infrastructure is left behind.
- SUCCESS/ERROR is reported to the platform; DETECTION/PREVENTION expectations
  are scored by the relevant runtime detection collectors.

## Credentials

Credentials are provided per inject through the contract fields. Secrets that
Stratus reads from disk (GCP service account key, kubeconfig) are written to a
temp file only for the detonation, restricted to the owner, and removed
afterwards (including on the failure path). Credentials are never persisted in
`config.yml`/`.env` and never logged.

## Development

```bash
poetry install
poetry run python -m unittest
```

## Icon

`stratus/img/icon-stratus.png` is the official Stratus Red Team badge flattened
onto a solid opaque background, per the injector icon standard
(OpenAEV-Platform/injectors#305).
