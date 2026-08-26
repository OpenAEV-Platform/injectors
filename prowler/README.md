# OpenAEV Prowler Injector

The Prowler injector foundation registers Prowler with OpenAEV. Provider and
account inputs, credentials, execution, mapping, routes, and contracts are not
startup configuration and remain outside this chunk.

## Configuration

| Environment variable | Configuration key | Purpose |
|---|---|---|
| `OPENAEV_URL` | `openaev.url` | OpenAEV server URL |
| `OPENAEV_TOKEN` | `openaev.token` | OpenAEV API token |
| `OPENAEV_TENANT_ID` | `openaev.tenant_id` | Optional tenant identifier |
| `INJECTOR_ID` | `injector.id` | Unique injector identifier |
| `INJECTOR_NAME` | `injector.name` | Injector display name |
| `INJECTOR_LOG_LEVEL` | `injector.log_level` | Runtime log level |
| `PROWLER_EXECUTABLE_PATH` | `prowler.executable_path` | Absolute path to the Prowler executable (default: `/usr/local/bin/prowler`) |

Copy `config.yml.sample` to the ignored `config.yml` for local use, or supply
the equivalent environment variables. Never commit real tokens.

`prowler.executable_path` must be nonblank and absolute. Startup does not
require the file to exist; executable resolution happens immediately before a
future assessment execution.

## Run

```shell
python -m prowler
```

The CHK.001 foundation starts with zero assessment contracts. Contract catalog
registration is deferred to CHK.006.

## Provider input boundary

Provider selection, account or target values, and credentials are not injector
startup configuration. They will be supplied per OpenAEV form contract so that
credential changes do not require redeploying the injector. CHK.002 provides
only reusable, strict provider input models; it does not register forms, routes,
or contracts.
