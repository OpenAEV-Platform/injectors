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
    - [Supported Contracts](#supported-contracts)
    - [Target Selection](#target-selection)
    - [Resources](#resources)

---

## Prerequisites

This injector uses [NetExec](https://www.netexec.wiki/).

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

> The Docker image **already contains NetExec**. No further installation is needed inside the container.

### Manual Deployment

1. Create a `config.yml` file based on `config.yml.sample`
2. Adjust the configuration values to match your environment

#### Prerequisites

* **NetExec must be installed locally** and accessible via the command line (`netexec` command).
* You can install it
  from: [https://www.netexec.wiki/getting-started/installation](https://www.netexec.wiki/getting-started/installation)

* Python package manager **Poetry** (version 2.1 or later)

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

Before submitting any **Pull Request**, contributors **must** format the codebase using **isort** and **black**.

```shell
poetry run isort --profile black .
poetry run black .
```

#### Run the Injector

```shell
poetry run python -m netexec.openaev_netexec
```

## Behavior

The NetExec injector performs **contract-based network reconnaissance and authentication checks** by dynamically
building and executing **NetExec commands** based on the contract configuration and user inputs.

Each execution translates contract fields (targets, credentials, and options) into a NetExec command and runs it against
the selected targets.

## Supported Contracts

The injector supports **10 protocols** via dedicated contracts:

| Contract | Protocol | Default Port | Authentication | Command Execution |
|----------|----------|--------------|----------------|-------------------|
| **NetExec - SMB** | SMB | 445 | username, password, NTLM hash, domain | `-x` (CMD), `-X` (PowerShell) |
| **NetExec - SSH** | SSH | 22 | username, password, SSH key file | `-x` (CMD) |
| **NetExec - LDAP** | LDAP | 389 | username, password, NTLM hash, domain | — |
| **NetExec - WinRM** | WinRM | 5985 | username, password, NTLM hash, domain | `-x` (CMD), `-X` (PowerShell) |
| **NetExec - MSSQL** | MSSQL | 1433 | username, password, NTLM hash, domain | `-x` (CMD), `-X` (PowerShell), `-q` (SQL) |
| **NetExec - RDP** | RDP | 3389 | username, password, NTLM hash, domain | `-x` (CMD), `-X` (PowerShell) |
| **NetExec - VNC** | VNC | 5900 | password | — |
| **NetExec - FTP** | FTP | 21 | username, password | — |
| **NetExec - WMI** | WMI | 135 | username, password, NTLM hash, domain | `-x` (CMD), `-X` (PowerShell), WMI query |
| **NetExec - NFS** | NFS | 111 | — (host-based) | — |

### Per-protocol options

**SMB**: `--shares`, `--users`, `--groups`, `--local-groups`, `--sessions`, `--loggedon-users`, `--computers`, `--rid-brute`, `--disks`, `--interfaces`, `--pass-pol`, `--local-auth`, `--sam`, `--lsa`, `--ntds`

**SSH**: `--sudo-check`, `--no-output`

**LDAP**: `--users`, `--groups`, `--computers`, `--dc-list`, `--get-sid`, `--active-users`, `--pass-pol`, `--pso`, `--trusted-for-delegation`, `--find-delegation`, `--password-not-required`, `--admin-count`, `--gmsa`, `--asreproast`, `--kerberoasting`, `--bloodhound`

**WinRM**: `--local-auth`, `--sam`, `--lsa`, `--dpapi`, `--no-output`

**MSSQL**: `--local-auth`, `--sam`, `--lsa`, `--rid-brute`, `--no-output`

**RDP**: `--local-auth`, `--screenshot`, `--nla-screenshot`, `--no-output`

**VNC**: `--screenshot`

**FTP**: `--ls`

**WMI**: `--local-auth`, `--no-output`

**NFS**: `--shares`, `--enum-shares`, `--ls`

## Structured Output Parsing

The injector extracts structured findings from NetExec command output. Each contract can produce multiple finding types beyond raw text.

### Finding Types

| Output Type | Field | Description | Mandatory Fields |
|---|---|---|---|
| `text` | `text` | Raw text output lines | — |
| `credentials` | `credentials` | Reusable credentials (passwords, NTLM hashes) | `username` + (`password` or `hash`) |
| `username` | `usernames` | Enumerated user accounts | `username` |
| `admin_username` | `admin_usernames` | Admin accounts (adminCount=1) | `username` |
| `share` | `shares` | SMB shares (excludes admin shares ending with `$`) | `share_name` + `permissions` |
| `group` | `groups` | AD / local groups | `group_name` |
| `computer` | `computers` | Computer accounts | `computer_name` |
| `password_policy` | `password_policy` | Domain password policy settings | `key` + `value` |
| `delegation` | `delegations` | Kerberos delegation configurations | `account` |
| `sid` | `sids` | Domain SID | `sid` |
| `vulnerability` | `vulnerabilities` | Vulnerability detection results | `name` + `status` |
| `account_with_password_not_required` | `accounts_pw_not_required` | Accounts with PASSWD_NOTREQD flag | `account` |
| `asreproastable_account` | `asreproastable_accounts` | AS-REP roastable accounts | `username` |
| `kerberoastable_account` | `kerberoastable_accounts` | Kerberoastable accounts | `username` |

### Contracts with Dedicated Output Parsers

| Contract | Finding Types Extracted |
|---|---|
| `--users` (SMB/LDAP) | credentials, usernames |
| `--active-users` (LDAP) | usernames |
| `--rid-brute` (SMB) | usernames (SidTypeUser only) |
| `--loggedon-users` (SMB) | usernames |
| `--admin-count` (LDAP) | admin_usernames |
| `--shares` (SMB) | shares |
| `--groups` (LDAP) | groups (with member count) |
| `--local-groups` (SMB) | groups (with RID) |
| `--computers` (LDAP) | computers |
| `--pass-pol` (SMB) | password_policy |
| `--trusted-for-delegation` (LDAP) | delegations |
| `--find-delegation` (LDAP) | delegations (with type and rights) |
| `--get-sid` (LDAP) | sids |
| `--password-not-required` (LDAP) | accounts_pw_not_required |
| `--asreproast` (LDAP) | asreproastable_accounts |
| `--kerberoasting` (LDAP) | kerberoastable_accounts |
| `--sam` (SMB) | credentials (NTLM hashes) |
| `--lsa` (SMB) | credentials (Kerberos keys, NTLM, cleartext) |
| `--ntds` (SMB) | credentials (NTLM hashes) |
| `-M dpapi_hash` (SMB) | credentials (DPAPI master key hashes) |
| `-M get_desc_users` (LDAP) | credentials (passwords in descriptions) |
| `-M user_desc` (SMB) | credentials (passwords in descriptions) |
| `-M spooler` (SMB) | vulnerabilities |
| `-M coerce_plus` (SMB) | vulnerabilities |
| `-M ldap-checker` (LDAP) | vulnerabilities |

> Contracts without a dedicated parser still produce `text` findings from their raw output.

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

## Example Executions

SMB share enumeration:

```bash
netexec smb 192.168.1.50 --shares
```

SSH authentication with command execution:

```bash
netexec ssh 192.168.1.50 -u admin -p Password123 -x "whoami"
```

LDAP user enumeration:

```bash
netexec ldap 192.168.1.10 -u admin -p Password123 -d CONTOSO --users
```

MSSQL SQL query:

```bash
netexec mssql 192.168.1.20 -u sa -p Password123 --local-auth -q "SELECT name FROM sys.databases"
```

## Resources

* [NetExec GitHub Repository](https://github.com/Pennyw0rth/NetExec)
* [NetExec Documentation](https://www.netexec.wiki/)
