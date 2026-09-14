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

The injector registers 32 concrete assessment routes in the validated
registry: 4 base provider routes (CHK.007–CHK.010), 7 service routes
(CHK.011–CHK.013), 14 compliance routes (CHK.014–CHK.016), 6
selectable routes (CHK.017): `aws/select-service`, `aws/select-compliance`,
`azure/select-service`, `azure/select-compliance`, `gcp/select-service`,
and `gcp/select-compliance`, and 1 universal route (CHK.017):
`universal`.

Every registered contract preserves each mapped CHK.005 finding as deterministic
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

On success, the mapped findings section remains first. A separate ruled
`[PROWLER] Raw OCSF evidence (bounded preview)` section follows it with the
artifact byte count, total decoded record count, no more than ten compact rows,
and an explicit omitted-record count. Those rows are projected only from finding
title/UID, status/code, severity, first-resource name/UID, cloud
provider/region/account, or the legacy provider UID. Descriptions, remediation,
resource data, arbitrary `unmapped` content, credentials, and console output do
not enter the preview. Empty artifacts report zero counts and remain successful.

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
Structured output is serialized and measured as UTF-8 before success rendering.
The callback accepts at most 32 MiB of encoded `execution_output_structured`; an
oversized projection closes as `structured_output_too_large` with actual and
accepted byte counts and no partial findings. Projection/JSON failures close as
`structured_output_failed`, while Rich failures remain `rendering_failed`. Each
path uses one callback attempt and no second render attempt.

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
Correlated secondary cleanup is not performed inside callback handling and
remains future work.

Artifact lifecycle failures are also closed and actionable. Missing, nonregular,
unreadable, and oversized artifacts, plus output-workspace preparation and cleanup
failures, each have a distinct failure code, fixed summary, and fixed action in
both ERROR metadata and the OpenAEV trace. When the process already returned, its
return code and stdout/stderr byte counts are retained as typed evidence; raw
output, exception text, and temporary paths remain excluded.

## Provider input boundary

Provider selection, account or target values, and credentials are not injector
startup configuration. Concrete contracts supply them per assessment. The
injector validates structure only: provider values must be nonblank, and an AWS
account must contain exactly 12 ASCII digits. Prowler enforces region, project,
and Kubernetes-context domain constraints at runtime. A runtime rejection is
returned as a safe `ERROR` result without logging or echoing submitted values.

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

## Selectable service and compliance contracts

CHK.017 adds the six selectable routes above on the unchanged CHK.004
seam; the 25 pre-existing routes are unchanged. Each selectable contract
adds exactly one mandatory single-select control after its provider
fields. The service dropdown offers the closed literal set of its
provider — AWS `iam`, `s3`, `ec2`; Azure `iam`, `storage`; GCP `iam`,
`compute` — and the compliance dropdown offers the four non-Kubernetes
Prowler frameworks suffixed with the provider name, for example
`cis_3.0_aws`, `nis2_gcp`, and `mitre_attack_azure`. The first offered
value is the default selection.

Validation is closed-set and value-free. A missing, non-list, or empty
select reports `select_missing`; more than one element reports
`select_multiple`; an element that is not an exact offered value reports
`select_unknown_value`. Rejections name only the field location and issue
type, never a submitted value, and stop before any client call. The
select key is stripped before the remaining form is validated against the
same strict provider model as the fixed routes, and a `provider` key is
still rejected first.

The chosen value is bound to the worker thread that parsed it and
cleared at the start of every parse, before any early return. The
pinned pyoaev 2.260521.0 `ListenQueue._process_message` (pyoaev
helpers) acks each RabbitMQ message on receipt and starts a fresh
worker thread per message — `basic_qos(prefetch_count=1)` does not
serialize because the ack precedes processing — so injections of the
same contract process concurrently against the one shared registry
instance per contract, and each injection's parse and execute provably
run on its own worker thread; on a reused thread (direct or test use)
the reset preserves the same safety. `safe_request_info` reports
`service=<value>` or `compliance=<value>` while a selection is held
and `service=unselected`/`compliance=unselected` otherwise.

Execution performs one mapped CHK.004 seam call carrying the held value as
the `service_selector` or `compliance_selector`, exactly like the fixed
service and compliance contracts. Executing with a mismatched provider
model or without a held selection raises before any call. Output
projection, Rich execution traces, the credential-file lifecycle,
artifact handling, and failure classification are inherited unchanged
from CHK.004–CHK.016.

The route meta-tokens `select-service` and `select-compliance` are
reserved under both route grammars: service routes read as
`<provider>/<service-literal>`, and compliance routes read as
`<framework>/<provider>` with the provider drawn from the closed set
aws, azure, gcp, and kubernetes. A rename of either token would only be
forced by a future Prowler service or compliance framework literally
named `select-service` or `select-compliance`.

## Universal selectable contract

CHK.017 also adds the single `universal` route with the provider
meta-token `all` and the family token `universal`; the 31 pre-existing
routes are unchanged. Its form opens with one mandatory single-select
provider control offering `aws`, `azure`, `gcp`, and `kubernetes`
(default `aws`), followed by the union of all fifteen provider
credential fields in the fixed provider order. Every credential field
is visible only when `prowler_provider` equals its own provider, and
the thirteen required fields are mandatory only under the same
condition (the two optional AWS fields carry visibility conditions
only). Two optional single-select scope controls close the form:
`prowler_service` offers the seven service routes and
`prowler_compliance` the fourteen compliance routes as canonical route
values (`aws/s3`, `cis/kubernetes`, …) with human-readable labels.
Kubernetes is offered here for the first time: its base fields and the
`cis/kubernetes` and `iso27001/kubernetes` compliance scopes, but no
service scope. The six selectable contracts keep their closed
non-Kubernetes choice sets unchanged.

Scope semantics are closed: both scope selects empty means the
selected provider's base scan; exactly one set means exactly that
service or compliance route; both set is rejected with `scope_conflict`
at the two scope locations; a scope whose provider part disagrees with
the selected provider is rejected with `scope_provider_mismatch` at
that scope key — all before any client call. The three select keys and
every field of the three non-selected providers are stripped
unconditionally and never validated or reported, so a wrong-provider
form fails exactly like the matching fixed provider contract. Select
validation reuses the closed vocabulary: `select_missing`,
`select_multiple`, and `select_unknown_value` at the select location,
plus the two scope-specific types above; no error ever names a
submitted value.

The parsed provider and both scope selections are bound to the worker
thread that parsed them: all three are reset at the start of every
parse before any early return, and set only after full validation
succeeds, so a failed parse never exposes a prior selection on a
reused thread and another thread's state is untouched. `execute`
requires the held provider and a matching provider model, runs one
CHK.004 seam call (base, service, or compliance) with the parsed
provider input and empty `check_filters`, and retains findings and
preview rows for the held provider name only. `safe_request_info`
reports `filters` as `base`, `service=<route>`, `compliance=<route>`,
or `unselected`, plus `selected_provider` as the held provider name or
`unselected`; traces report the parsed provider name, never the `all`
meta-token, and never forward free-form error text.

The route name `universal` is reserved: it is slash-free, so it can
never be read as a `<provider>/<service-literal>` or
`<framework>/<provider>` route, and it is not a closed provider
literal, so it is not a base route. The `all` meta-token is not a
provider literal and appears in no route name.

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
only the artifact byte size. The downstream mapper requires that captured
artifact as bytes or text, decodes it, maps every decoded record, retains only the
mapped findings and ten field-allowlisted preview rows, and then releases the full
decoded records. The byte count comes from the captured artifact and the record
count from the decoded collection; this is not a streaming or one-pass JSON
implementation. Console stdout remains separate and is never parsed as OCSF.

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
