# OpenAEV Prowler Injector

Run Prowler cloud-security assessments from OpenAEV and return the results to the platform.

## Requirements

- Python 3.11 or later
- An OpenAEV instance and valid connection configuration
- An installed Prowler executable, version 5.36.0, configured through `PROWLER_EXECUTABLE_PATH`

The injector emits Prowler 5.36.0 CLI arguments. It does not install or verify Prowler for you.

This injector is a plain Python process. It ships no Docker or Compose deployment and no NetExec integration.

## Configuration

Copy `config.yml.sample` to the ignored `config.yml`, or provide equivalent environment variables. Do not commit real tokens.

| Environment variable | Configuration key | Purpose |
|---|---|---|
| `OPENAEV_URL` | `openaev.url` | OpenAEV server URL |
| `OPENAEV_TOKEN` | `openaev.token` | OpenAEV API token |
| `OPENAEV_TENANT_ID` | `openaev.tenant_id` | Optional tenant identifier |
| `INJECTOR_ID` | `injector.id` | Injector identifier |
| `INJECTOR_NAME` | `injector.name` | Injector display name |
| `INJECTOR_LOG_LEVEL` | `injector.log_level` | Runtime log level |
| `PROWLER_EXECUTABLE_PATH` | `prowler.executable_path` | Nonblank absolute path to the Prowler executable. Default: `/usr/local/bin/prowler` |

## Run

From an installed injector package:

```shell
python -m prowler
```

The installed command is also available when the package has been installed with its script entry point:

```shell
ProwlerInjector
```

## Contracts and routes

The injector registers 32 assessment routes:

- **4 base provider routes:** `aws`, `azure`, `gcp`, and `kubernetes`
- **7 service routes:** AWS `iam`, `s3`, and `ec2`; Azure `iam` and `storage`; GCP `iam` and `compute`
- **14 compliance routes:** CIS, NIS2, ISO 27001, and MITRE ATT&CK where supported by the provider
- **6 selectable routes:** `aws/select-service`, `aws/select-compliance`, `azure/select-service`, `azure/select-compliance`, `gcp/select-service`, and `gcp/select-compliance`
- **1 universal route:** `universal`

Base routes run the selected provider assessment. Service and compliance routes run their fixed scope.

Selectable routes let an operator choose one supported service or compliance scope for AWS, Azure, or GCP. The universal route lets an operator select AWS, Azure, GCP, or Kubernetes, then optionally select one matching service or compliance scope. Without an optional scope, it runs the selected provider's base assessment.

## Inputs and outputs

Provider targets and credentials are supplied per assessment, not as injector startup configuration. GCP service-account JSON and Kubernetes kubeconfig are declared as plaintext form inputs at the OpenAEV contract boundary; they are not masked platform secret fields.

Each assessment returns every mapped finding as deterministic JSON text. Only findings whose expectation result is `FAILED` are projected as OpenAEV vulnerabilities; successful and ignored findings are not.

The injector does not log or echo credential content, but the plaintext boundary exposure above remains by design.

## Operational safety

GCP service-account JSON and Kubernetes kubeconfig credentials are written to temporary files while Prowler runs, and Prowler output goes to a temporary workspace directory. The injector cleans up its own temporary files and directories after normal completion or failure; it does not perform broad stale-file deletion.

An abrupt crash, forced termination, host failure, or power loss can leave plaintext credential files and temporary assessment-output files in the operating system temporary location. Secure the temporary volume and apply an appropriate stale-file cleanup policy.

## Troubleshooting

- Confirm `PROWLER_EXECUTABLE_PATH` is a nonblank absolute path to the intended Prowler executable.
- Check OpenAEV URL, token, tenant configuration where applicable, and injector identity settings.
- For authentication or permission failures, verify the per-assessment provider credentials and their permitted scope.
