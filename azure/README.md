# OpenAEV Azure + Entra ID Injector

Emulates Microsoft Azure and Entra ID attack techniques using
[Stratus Red Team](https://stratus-red-team.cloud/), the self-contained
adversary-emulation binary from Datadog. Each inject detonates a granular cloud
or identity TTP (with automatic `--cleanup`) so the Microsoft Sentinel and
Microsoft Defender collectors can validate detection and prevention.

## How it works

- The injector wraps the `stratus` CLI through the shared `StratusExecutor`
  (`injector_common/injector_common/stratus_executor.py`), also used by the GCP
  and Kubernetes injectors.
- A contract carries the target service principal credentials
  (`azure_tenant_id`, `azure_subscription_id`, `azure_client_id`,
  `azure_client_secret`) and either a selected Stratus technique or a custom
  technique id. The injector maps these fields to the `AZURE_TENANT_ID`,
  `AZURE_SUBSCRIPTION_ID`, `AZURE_CLIENT_ID` and `AZURE_CLIENT_SECRET`
  environment variables that Stratus Red Team expects.
- On detonation the injector reports SUCCESS/ERROR back to the platform; the
  configured DETECTION/PREVENTION expectations are then scored by the Microsoft
  Sentinel / Defender collectors.

## Credentials

Per-target Azure credentials are provided at inject time through the contract
fields - never stored in `config.yml`/`.env`. Only the OpenAEV connection
settings live in the injector configuration.

## Configuration

See `config.yml.sample` (manual deployment) and `.env.sample` (Docker).

## Development

```bash
poetry install
poetry run python -m unittest
```

## Icon

`azure_injector/img/icon-azure.png` must follow the injector icon standard
(square 1:1, 512x512 PNG, solid opaque background, genuine Microsoft Azure
artwork) - see OpenAEV-Platform/injectors#305.
