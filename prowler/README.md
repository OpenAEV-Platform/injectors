# OpenAEV Prowler Injector

The Prowler injector foundation registers Prowler with OpenAEV. Assessment
providers, credentials, execution, mapping, routes, and contracts are outside
CHK.001 and are intentionally not configured here.

## Configuration

| Environment variable | Configuration key | Default | Mandatory | Purpose |
|---|---|---|---|---|
| `OPENAEV_URL` | `openaev.url` | / | Yes | OpenAEV server URL |
| `OPENAEV_TOKEN` | `openaev.token` | / | Yes | OpenAEV API token |
| `OPENAEV_TENANT_ID` | `openaev.tenant_id` | / | No | Optional tenant identifier |
| `INJECTOR_ID` | `injector.id` | / | Yes | Unique injector identifier |
| `INJECTOR_NAME` | `injector.name` | `Prowler` | No | Injector display name |
| `INJECTOR_LOG_LEVEL` | `injector.log_level` | `error` | No | Runtime log level |

Copy `config.yml.sample` to the ignored `config.yml` for local use, or supply
the equivalent environment variables. Never commit real tokens.

## Run

```shell
python -m prowler
```

The CHK.001 foundation starts with zero assessment contracts. Contract catalog
registration is deferred to CHK.006.
