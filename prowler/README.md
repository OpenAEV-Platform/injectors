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

CHK.003 accepts this configured absolute path at its validated command-request
boundary and preserves it in the immutable execution specification. The later
Prowler adapter must pass `str(config.prowler.executable_path)` into that request;
the generic engine does not hardcode a Prowler binary location.

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

`aws_endpoint_url` is an optional per-assessment provider input for AWS, like
its credentials. When supplied, it must be an absolute HTTP or HTTPS URL with a
host and must not contain user information, a query, a fragment, or whitespace.
Paths and valid ports are allowed, including endpoints on localhost, private
networks, and container services. The accepted value remains an ordinary string,
and validation does not check network reachability.

## Prowler 5.36 CLI compatibility

CHK.004 targets the installed `prowler` distribution version 5.36.0. Its
Kubernetes parser registers `--context` for selecting a kubeconfig context;
`--kube-context` is not registered. The adapter therefore emits
`--kubeconfig-file <temporary path> --context <name>`. This installed parser
evidence supersedes the stale proof-of-concept/contract spelling.

## Contract credential-file lifecycle

AWS and Azure credentials remain `SecretStr` environment values and are not
written to files. Prowler 5.36 requires filesystem paths for GCP service-account
JSON and Kubernetes kubeconfig input. Immediately before launching Prowler, one
contract execution therefore writes that plaintext credential to a randomly
named file inside a unique OS temporary directory. The file is closed before
the subprocess starts so native Windows can reopen it. It persists for the
Prowler command runtime and is deleted in `finally`, followed by its private
directory, whether execution returns or raises. The immutable command
specification and result may retain the now-stale temporary path, but never the
file content.

On POSIX, the directory is mode `0700` and the file is mode `0600`. Native
Windows relies on the current user's temp-directory ACL. Python `chmod` cannot
guarantee POSIX-equivalent ACL semantics on Windows, so this injector does not
claim that Windows permissions are owner-only. Docker and Kubernetes pod
ephemeral storage can reduce exposure, but does not eliminate it.

An abrupt interpreter crash, forced kill, host failure, or power loss can occur
before `finally` and leave plaintext residue in the OS temp location. Operators
must secure and preferably encrypt the temp volume and clean stale files under
their own retention policy. The injector deliberately performs no broad stale
cleanup that could delete unrelated files.

Each created client is one-shot and releases its copied provider input on the
first terminal run path. Python immutable strings and copies cannot be
guaranteed to be zeroized; the upstream OpenAEV injection payload may retain
credential values until `process_message` returns.
