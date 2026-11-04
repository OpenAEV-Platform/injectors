# OpenAEV BloodHound AD Injector

Runs the [BloodHound.py](https://github.com/dirkjanm/BloodHound.py) Active
Directory collector (SharpHound-compatible) and surfaces users, computers and
privilege-escalation attack paths (Kerberoastable, AS-REP roastable) as
findings.

## Contract

- BloodHound - Collect AD attack paths: fields for domain, username, password
  and domain controller. Produces VULNERABILITY (attack paths exist) and
  DETECTION (enumeration detected) expectations.

## Credentials

The AD credentials are provided per inject through the contract fields and are
never logged (the password argument is redacted in logs).

## Configuration variables

The injector is configured either through environment variables (recommended, read from `docker-compose.yml` / the `.env` file for a Docker deployment) or through a `config.yml` file (for a manual deployment). Copy the provided `.env.sample` / `config.yml.sample` and fill in the values flagged with `ChangeMe`.

### OpenAEV environment variables

| Parameter         | config.yml          | Docker environment variable | Mandatory | Description                                                                        |
|-------------------|---------------------|-----------------------------|-----------|------------------------------------------------------------------------------------|
| OpenAEV URL       | `openaev.url`       | `OPENAEV_URL`               | Yes       | The URL of the OpenAEV platform. Must be reachable from where the injector runs.   |
| OpenAEV Token     | `openaev.token`     | `OPENAEV_TOKEN`             | Yes       | The administrator token of the OpenAEV platform.                                   |
| OpenAEV Tenant ID | `openaev.tenant_id` | `OPENAEV_TENANT_ID`         | No        | Tenant identifier for multi-tenant deployments. When set, it must be a valid UUID. |

### Base injector environment variables

| Parameter     | config.yml           | Docker environment variable | Default      | Mandatory | Description                                                     |
|---------------|----------------------|-----------------------------|--------------|-----------|-----------------------------------------------------------------|
| Injector ID   | `injector.id`        | `INJECTOR_ID`               | /            | Yes       | A unique `UUIDv4` identifier for this injector instance.        |
| Injector Name | `injector.name`      | `INJECTOR_NAME`             | BloodHound AD | No       | The name of the injector as shown in OpenAEV.                   |
| Log Level     | `injector.log_level` | `INJECTOR_LOG_LEVEL`        | error        | No        | Verbosity of the logs. One of `debug`, `info`, `warn`, `error`. |

## Development

```bash
poetry install
poetry run python -m unittest
```

## Icon

`bloodhound_injector/img/icon-bloodhound.png` must follow the injector icon
standard (square 1:1, 512x512 PNG, solid opaque background, genuine BloodHound
artwork) - see OpenAEV-Platform/injectors#305.
