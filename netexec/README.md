# OpenAEV NetExec Injector

## Table of Contents

- [OpenAEV NetExec Injector](#openaev-netexec-injector)
    - [Prerequisites](#prerequisites)
    - [Configuration variables](#configuration-variables)
        - [OpenAEV environment variables](#openaev-environment-variables)
        - [Base injector environment variables](#base-injector-environment-variables)
    - [Deployment](#deployment)
        - [Docker Deployment](#docker-deployment)
        - [Manual Deployment](#manual-deployment)
    - [Behavior](#behavior)
        - [Template Selection](#template-selection)
        - [Target Selection](#target-selection)
    - [Resources](#resources)

---

## Prerequisites

This injector uses [NetExex](https://www.netexec.wiki/smb-protocol/enumeration).

This injector communicates with the OpenAEV platform through **RabbitMQ**, using the configuration provided by OpenAEV.

To function properly, the injector **must be able to reach the RabbitMQ service** (hostname and port) defined in the
OpenAEV configuration.

## Configuration

Configuration values can be provided either:

* via `docker-compose.yml` (Docker deployment), or
* via `config.yml` (manual deployment).

### OpenAEV Environment Variables

The following parameters are required to connect the injector to the OpenAEV platform:

| Parameter     | `config.yml` | Docker Variable | Mandatory | Description                                         |
|---------------|--------------|-----------------|-----------|-----------------------------------------------------|
| OpenAEV URL   | `url`        | `OPENAEV_URL`   | Yes       | Base URL of the OpenAEV platform.                   |
| OpenAEV Token | `token`      | `OPENAEV_TOKEN` | Yes       | Admin API token configured in the OpenAEV platform. |

### Injector Environment Variables

The following parameters control the injector runtime behavior:

| Parameter     | `config.yml` | Docker Variable      | Default | Mandatory | Description                                             |
|---------------|--------------|----------------------|---------|-----------|---------------------------------------------------------|
| Injector ID   | `id`         | `INJECTOR_ID`        | —       | Yes       | Unique `UUIDv4` identifying this injector instance.     |
| Injector Name | `name`       | `INJECTOR_NAME`      | —       | Yes       | Human-readable name of the injector.                    |
| Log Level     | `log_level`  | `INJECTOR_LOG_LEVEL` | `info`  | Yes       | Logging verbosity: `debug`, `info`, `warn`, or `error`. |

## Deployment

### Docker Deployment

Build the Docker image using the provided `Dockerfile`.

```shell
docker build --build-context injector_common=../injector_common . -t openaev/injector-netexec:latest
```

Then configure the environment variables in `docker-compose.yml` and start the injector:

```shell
docker compose up -d
```

> ✅ The Docker image **already contains NetExec**. No further installation is needed inside the container.

### Manual Deployment

1. Create a `config.yml` file based on `config.yml.sample`
2. Adjust the configuration values to match your environment

#### Prerequisites

* **NetExec must be installed locally** and accessible via the command line (`netexec` command).
* You can install it
  from: [https://www.netexec.wiki/getting-started/installation](https://www.netexec.wiki/getting-started/installation)

* Python package manager **Poetry** (version 2.1 or later)
  👉 [https://python-poetry.org/](https://python-poetry.org/)

#### Installation

**Production environment**

```shell
poetry install --extras prod
```

**Development environment**

For development, you should also clone the `pyoaev` repository following the instructions provided in the OpenAEV
documentation.

```shell
poetry install --extras dev
```

## Development

This project follows strict code formatting rules to ensure consistency and readability across the OpenAEV ecosystem.

Before submitting any **Pull Request**, contributors **must** format the codebase using **isort** and **black**.

### Code Formatting

The following tools are required (already included in the development dependencies):

* **isort** – import sorting
* **black** – code formatter

Run them from the project root:

```shell
poetry run isort --profile black .
poetry run black .
```

Both commands must complete **without errors or changes** before opening a PR.

> ⚠️ Pull Requests that do not respect formatting rules may be rejected or require additional review cycles.

#### Run the Injector

```shell
poetry run python -m netexec.openaev_netexec
```

#### Test it

SMB de test

```
podman run -d --name smb-test --network openaev-dev_default -p 445:445 dperson/samba -u "testuser;testpass" -s "share;/share;yes;no;no;testuser"
```

Run command to test

```
netexec smb smb-test -u testuser -p testpass --shares
```

## Behavior

The NetExec injector performs **contract-based network reconnaissance and authentication checks** by dynamically
building and executing **NetExec commands** based on the contract configuration and user inputs.

Each execution translates contract fields (targets, credentials, and options) into a NetExec command and runs it against
the selected targets.

NetExec is used as a **client-only tool**: it connects to remote services (such as SMB) and never exposes or hosts
services itself.

## Supported Contracts

The injector currently supports **SMB-based contracts**, focused on authentication checks and safe enumeration actions.

### SMB Authentication Contract

This contract allows validating credentials and performing controlled SMB enumeration using NetExec.

Supported SMB actions include:

* Share enumeration
* User enumeration
* Group enumeration
* Session enumeration
* Logged-on user discovery

Only **non-destructive, read-only actions** are exposed.

## Target Selection

Targets are resolved using the `target_selector` field defined in the contract.

### When the target type is **Assets**

| Selected Property | Asset Field Used              |
|-------------------|-------------------------------|
| Seen IP           | `endpoint_seen_ip`            |
| Local IP          | First entry in `endpoint_ips` |
| Hostname          | `endpoint_hostname`           |

### When the target type is **Manual**

Targets are provided directly as **comma-separated IP addresses or hostnames**.

## Options

The injector supports the following SMB options, mapped directly to NetExec arguments:

* `--shares` — Enumerate SMB shares
* `--users` — Enumerate users
* `--groups` — Enumerate groups
* `--sessions` — List active SMB sessions
* `--loggedon-users` — List currently logged-on users

If no option is explicitly selected, the injector defaults to a **safe enumeration action** (typically `--shares`) to
ensure meaningful output.

## Example Executions

Basic SMB share enumeration:

```bash
netexec smb 192.168.1.50 --shares
```

SMB authentication test with credentials:

```bash
netexec smb 192.168.1.50 -u admin -p Password123
```
## Resources

* [NetExec GitHub Repository](https://github.com/Pennyw0rth/NetExec)
* [NetExec Documentation](https://github.com/Pennyw0rth/NetExec/wiki)