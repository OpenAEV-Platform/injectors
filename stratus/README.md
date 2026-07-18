# OpenAEV Stratus Red Team Injector

Emulates granular cloud and container adversary techniques using
[Stratus Red Team](https://stratus-red-team.cloud/). A single injector exposes
one contract per Stratus platform, so attack scenarios are organized by
technique rather than split across one injector per cloud.

## Supported platforms

Each platform is a dedicated injector contract with its own credentials and its
own technique catalog (mirroring `stratus list --platform <platform>`):

| Contract | Platform | Credentials |
|---|---|---|
| AWS - Detonate Stratus technique | AWS | Access key id / secret, optional session token, region |
| Azure - Detonate Stratus technique | Azure | Tenant / subscription / client id / client secret |
| Entra ID - Detonate Stratus technique | Entra ID | Tenant / client id / client secret |
| Google Cloud Platform - Detonate Stratus technique | GCP | Project id + service account key (JSON) |
| Kubernetes - Detonate Stratus technique | Kubernetes | Kubeconfig (YAML) |
| Amazon EKS - Detonate Stratus technique | EKS | AWS access key id / secret, optional session token, region |

## How it works

- Each contract carries the platform credentials and a Stratus technique
  selector (with a free-form "custom technique id" override for any technique in
  the pinned Stratus release).
- The injector resolves the target platform from the contract id, builds the
  Stratus process environment, and detonates the selected technique with
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
