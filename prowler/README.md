# OpenAEV Prowler Injector

The Prowler injector foundation registers Prowler with OpenAEV. CHK.006 adds
reusable contract declarations, output projection, a validated concrete-contract
registry, runtime dispatch, and the canonical route catalog. It does not register
the future concrete assessment contracts.

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

The injector still starts with zero assessment contracts. CHK.006 provides the
shared executable boundary; CHK.007–CHK.016 will supply and register concrete
contracts directly in the validated registry.

Every future contract preserves each mapped CHK.005 finding as deterministic
JSON text. FAILED findings are additionally projected as OpenAEV vulnerability
outputs. SUCCESS and IGNORED findings are not projected as vulnerabilities, and
Prowler cloud resource identifiers are not claimed to be OpenAEV asset UUIDs.

### Rich execution traces

Execution messages are deterministic Rich reports captured without terminal
colour at a fixed width. The base contract supplies bounded default columns for
CHK.005's flattened `OpenAevFinding` fields; a concrete contract can override
`output_trace_config()` to select route-specific columns, including nested,
numeric-index, wildcard, and fallback display paths. Missing and empty results
remain valid display states, while row and cell limits prevent oversized
callbacks.

The trace is presentation only. It is separate from registered contract outputs
and does not alter `execution_output_structured`. The renderer receives an
explicit allowlist built from the parsed provider model (route, filters, and
non-secret account, subscription, project, context, region, or requested-provider
context). It never receives the raw form payload, credential fields, command
environment or arguments, temporary credential paths, or raw stderr. Runtime
errors use one closed failure classification with a fixed `failure_summary` that
says what happened and why, plus separate fixed `operator_guidance` that says what
to do next. ERROR metadata and the OpenAEV trace share the same code, reason,
action, sanitized inject correlation, canonical contract/route/provider identity,
and applicable typed evidence. The trace never receives parsed provider input, so
account, subscription, project, and Kubernetes context do not appear in an error
unless the contract already rendered them from its existing safe request summary.
Structured output is serialized before success rendering. If serialization or
Rich rendering fails, the callback uses the same bounded plain diagnostics with
one callback attempt and no second render attempt.

The runtime emits fixed `[PROWLER_INJECTOR]` lifecycle diagnostics through the
injector logger. Startup INFO identifies the configured injector, registered
contract count, executable path, and whether that path is absolute, exists, is a
regular file, and is executable. Assessment events distinguish received,
reception acknowledged, contract resolved, input validated, execution starting,
terminal completion/failure, and callback completion/failure. Every usable-inject
event carries a log-safe inject ID (`[A-Za-z0-9._:-]`, at most 128 characters).
Malformed or oversized IDs use a bounded deterministic `invalid:<sha256-prefix>`
correlation, so events remain distinguishable without logging the raw ID. Events
also carry a controlled stage and bounded monotonic `elapsed_ms`; the logger
supplies wall-clock timestamps. Once resolution succeeds,
the canonical contract ID, route, and provider accompany every later event.
Malformed envelopes receive a closed reason code without payload data.

Successful and callback diagnostics also include approved provider facts: AWS
account, region, normalized endpoint origin (`scheme://host[:port]`), and
session-token/endpoint-override presence;
Azure subscription and provider with credential-presence booleans; GCP project
with a credential-presence boolean; or Kubernetes context with a
credential-presence boolean. AWS access keys, Azure tenant/client ID values, and
all credential material remain excluded.

Known failures add only evidence derived from the typed command specification,
engine error, or result: configured/actual executable paths and stat checks;
allowlisted process-start cause classes; configured timeout or output limit;
parser name; return code; and captured stdout/stderr byte counts. OCSF decode and
mapping failures are reported as `parsing_failed` with an allowlisted code, bounded
record index, and closed source-path evidence. Input rejection
uses only bounded field locations and issue types. The operational executable path
is intentionally visible, but raw form values, credentials, arguments,
environment values, stdin, stdout/stderr contents, exception text or traceback,
callback payloads, finding content, GCP JSON, kubeconfig, and temporary credential
paths are never logged or added to error traces. ERROR logging keeps
`exc_info=False`. Metadata construction and log emission are both best-effort, so
they cannot gate assessment delivery. Callback events distinguish
`assessment_status` from `delivery_status`; a failed reception stops before any
terminal callback is attempted.

## Provider input boundary

Provider selection, account or target values, and credentials are not injector
startup configuration. Concrete contracts supply them per assessment and
CHK.006 converts form data immediately into CHK.002's strict provider models.

### Plaintext credential limitation

At the current pyoaev/OpenAEV contract boundary, Prowler credential fields use
ordinary `ContractText` or `ContractTextArea` controls. They are **plaintext
inputs**; this implementation does not claim masking or secret-field protection.
Credential fields have no defaults, are never intentionally logged or echoed,
and are converted immediately to `SecretStr`-backed provider models after form
submission. This limits handling inside the injector but does not remove the
plaintext platform-boundary exposure. Value-free validation diagnostics may name
the rejected credential field and error type, but never its submitted value.

A future iteration will migrate these fields to credential references. CHK.006
does not extend pyoaev or the platform with a new secret-field mechanism.

`aws_endpoint_url` is an optional per-assessment provider input for AWS, like
its credentials. When supplied, it must be an absolute HTTP or HTTPS URL with a
host and must not contain user information, a query, a fragment, or whitespace.
Paths and valid ports are allowed, including endpoints on localhost, private
networks, and container services. The accepted value remains an ordinary string,
and validation does not check network reachability.

AWS account IDs contain exactly 12 ASCII digits. Contract validation reports the
safe field/type structure and gives operators a fixed correction sentence without
echoing the rejected value. Empty OpenAEV controls for `aws_session_token` and
`aws_endpoint_url` are treated as omitted only at the AWS contract boundary;
direct provider-model validation remains strict.

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

## Assessment output storage

CHK.004 does not parse Prowler's console stream as OCSF. Each assessment owns a
unique controlled temporary output directory and tells Prowler to write the
single expected artifact as `findings.ocsf.json` (`--output-filename findings`
with `-M json-ocsf`). Console stdout and stderr remain bounded diagnostics; the
artifact is opened only at its exact path as a regular, non-symlink file and is
read incrementally to its separate 100 MiB limit. CHK.004 debug metadata reports
only the artifact byte size; record counting belongs to the downstream mapper.

On Linux/POSIX, a writable directory at `/dev/shm` is preferred and labelled
`memory_tmpfs`, keeping normal output in memory-backed temporary storage. It is
selected only when a safe free-capacity probe reports at least the 100 MiB
artifact limit plus a 16 MiB safety margin for Prowler's additional temporary or
nested output. If `/dev/shm` is absent, unsuitable, undersized, cannot be probed,
or fails workspace creation, the injector makes one attempt in the portable
system temporary location labelled `filesystem_temp`, which may be disk-backed.
Windows always uses that system-temp fallback and relies on its native
temporary-directory ACL rather than making a POSIX permission claim. Owned
output directories use mode `0700` on POSIX.

On native Windows, Python does not expose the POSIX `O_NOFOLLOW` guarantee used
to reject symlink substitution at open time. Regular-file checks before and
after open, plus device/inode identity checks, are therefore a best-effort
reparse-point defence inside the randomly named controlled directory. This
fallback does not claim atomic reparse-point exclusion on native Windows;
operators must secure the system temporary-directory ACL against untrusted
writers.

The complete owned output tree, including any nested compliance output, is
recursively removed on every normal success or failure path. Cleanup is
idempotent and never scans or deletes sibling temporary paths. An abrupt crash,
forced kill, host failure, or power loss can still bypass controlled cleanup and
leave output residue. Operators must protect both `/dev/shm` and the portable
disk fallback according to the sensitivity of assessment findings and apply
their own stale-file policy after abnormal termination.
