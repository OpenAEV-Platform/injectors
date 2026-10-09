# OpenAEV Prowler Injector

Run Prowler cloud-security assessments from OpenAEV and return the results to the platform.

## Requirements

- An OpenAEV instance and valid connection configuration
- Prowler 5.36.0, reachable at `PROWLER_EXECUTABLE_PATH` (default `/usr/local/bin/prowler`)
- Python 3.11 or later when running from source

The injector emits Prowler 5.36.0 CLI arguments. The Docker image bundles Prowler 5.36.0 in its own virtual environment, linked to `/usr/local/bin/prowler`: the Prowler package uses the same `prowler` import name as this injector and pins a different pydantic version, so the two cannot share an environment. When running from source, install Prowler the same way and point `PROWLER_EXECUTABLE_PATH` at its `prowler` executable.

## Configuration

Copy `config.yml.sample` to the ignored `config.yml`, or provide equivalent environment variables. Do not commit real tokens.

| Environment variable | Configuration key | Default | Mandatory | Purpose |
|---|---|---|---|---|
| `OPENAEV_URL` | `openaev.url` | / | Yes | OpenAEV server URL |
| `OPENAEV_TOKEN` | `openaev.token` | / | Yes | OpenAEV API token |
| `OPENAEV_TENANT_ID` | `openaev.tenant_id` | / | No | Optional tenant identifier |
| `INJECTOR_ID` | `injector.id` | / | Yes | Injector identifier |
| `INJECTOR_NAME` | `injector.name` | `Prowler` | No | Injector display name |
| `INJECTOR_LOG_LEVEL` | `injector.log_level` | `error` | No | Runtime log level |
| `PROWLER_EXECUTABLE_PATH` | `prowler.executable_path` | `/usr/local/bin/prowler` | No | Nonblank absolute path to the Prowler executable |

## Run

With Docker, using the `openaev/injector-prowler` image and the provided `docker-compose.yml`:

```shell
docker compose up -d
```

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

AWS also accepts an optional `aws_endpoint_url` per-assessment provider input. When supplied, it must be an absolute HTTP or HTTPS URL with a host and no user information, query, fragment, or whitespace; it is passed to Prowler as `AWS_ENDPOINT_URL`.

Each assessment returns every mapped finding as deterministic JSON text. Only findings whose expectation result is `FAILED` are projected as OpenAEV vulnerabilities; successful and ignored findings are not.

The injector does not log or echo credential content, but the plaintext boundary exposure above remains by design.

## Operational safety

AWS and Azure credentials are passed to Prowler as environment values and are never written to files. GCP service-account JSON and Kubernetes kubeconfig credentials are written as plaintext to a randomly named temporary file that persists only for the Prowler command runtime and is deleted in `finally`, whether execution succeeds or fails. Prowler output goes to a separate temporary workspace directory. The injector cleans up its own temporary files and directories after normal completion or failure; it does not perform broad stale-file deletion.

On POSIX, credential files are owner-only (`0600`) inside owner-only (`0700`) directories. On Windows, the injector relies on the current user's temporary-directory ACL and does not claim owner-only permissions. Docker or Kubernetes pod ephemeral storage reduces exposure but does not eliminate it.

An abrupt crash, forced termination, host failure, or power loss can leave plaintext credential files and temporary assessment-output files in the operating system temporary location. Secure and preferably encrypt the temporary volume and apply an appropriate stale-file cleanup policy. Python strings cannot be guaranteed to be zeroized, so credential values may remain in process memory until the injection completes.

## Assessment output storage

Each assessment writes Prowler's OCSF output to a unique, randomly named controlled directory. On Linux, memory-backed `/dev/shm` is preferred when it has room for the 100 MiB artifact limit plus a safety margin; otherwise the system temporary location is used. The artifact is read only at its exact path as a regular, non-symlink file.

On native Windows, Python does not provide the POSIX `O_NOFOLLOW` guarantee. Regular-file and device/inode identity checks inside the controlled directory are a best-effort reparse-point defence; the injector does not claim atomic reparse-point exclusion. Secure the system temporary-directory ACL against untrusted writers.

## Troubleshooting

- Confirm `PROWLER_EXECUTABLE_PATH` is a nonblank absolute path to the intended Prowler executable.
- Check OpenAEV URL, token, tenant configuration where applicable, and injector identity settings.
- For authentication or permission failures, verify the per-assessment provider credentials and their permitted scope.
