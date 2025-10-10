# OpenAEV Nuclei Injector

## Table of Contents

- [OpenAEV Nuclei Injector](#openaev-nuclei-injector)
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

This injector uses [ProjectDiscovery Nuclei](https://github.com/projectdiscovery/nuclei) to scan assets.

Depending on your deployment method:

- When using the **Docker deployment**, **Nuclei is bundled** within the image.
- When running manually (e.g., in development), **Nuclei must be installed locally** and available in the system's `PATH`.

In both cases, for the injector to operate correctly:

- It **must be able to reach the OpenAEV platform** via the URL you provide (through `OPENAEV_URL` or `config.yml`).
- It **must be able to reach the RabbitMQ broker** used by the OpenAEV platform.

---

## Configuration variables

Configuration is provided either through environment variables (Docker) or a config
file (`config.yml`, manual).

### OpenAEV environment variables

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
|---------------|------------|-----------------------------|-----------|------------------------------------------------------|
| OpenAEV URL   | url        | `OPENAEV_URL`               | Yes       | The URL of the OpenAEV platform.                     |
| OpenAEV Token | token      | `OPENAEV_TOKEN`             | Yes       | The default admin token set in the OpenAEV platform. |

### Base injector environment variables

| Parameter                               | config.yml                                      | Docker environment variable                                | Default | Mandatory | Description                                                                                       |
|-----------------------------------------|-------------------------------------------------|------------------------------------------------------------|---------|-----------|---------------------------------------------------------------------------------------------------|
| Injector ID                             | id                                              | `INJECTOR_ID`                                              | /       | Yes       | A unique `UUIDv4` identifier for this injector instance.                                          |
| Injector Name                           | name                                            | `INJECTOR_NAME`                                            |         | Yes       | Name of the injector.                                                                             |
| Log Level                               | log_level                                       | `INJECTOR_LOG_LEVEL`                                       | info    | Yes       | Determines the verbosity of the logs. Options: `debug`, `info`, `warn`, or `error`.               |
| External contracts maintenance schedule | external_contracts_maintenance_schedule_seconds | `INJECTOR_EXTERNAL_CONTRACTS_MAINTENANCE_SCHEDULE_SECONDS` | 86400   | No        | With every tick, trigger a maintenance of the external contracts (e.g. based on Nuclei templates) |

---

## Deployment

### Docker Deployment

Build the Docker image using the provided `Dockerfile`.

```bash
docker build docker build --build-context common=../common .  -t openaev/injector-nuclei:latest
````

Edit the `docker-compose.yml` file with your OpenAEV configuration, then start the container:

```bash
docker compose up -d
```

> ✅ The Docker image **already contains Nuclei**. No further installation is needed inside the container.

---

### Manual Deployment

#### Prerequisites

* **Nuclei must be installed locally** and accessible via the command line (`nuclei` command).
* You can install it from: [https://github.com/projectdiscovery/nuclei#installation](https://github.com/projectdiscovery/nuclei#installation)

#### Configuration

1. Copy `nuclei/config.yml.sample` to `nuclei/config.yml` and edit the relevant values.
2. Install Python dependencies (ideally in a virtual environment):

```bash
pip3 install -r requirements.txt
```

3. Run the injector:

```bash
cd src
python3 -m nuclei.openaev_nuclei
```

---

## Behavior

The Nuclei injector supports contract-based scans by dynamically constructing and executing Nuclei
commands based on provided tags or templates.

### Supported Contracts

The following scan types are supported via `-tags`:

- Cloud
- Misconfiguration
- Exposure
- Panel
- XSS
- WordPress
- HTTP

The CVE scan uses the `-tags cve` argument and enforces JSON output.

The Template scan accepts a manual template via `-t <template>` or `template_path`.

Additionally, contracts dedicated to scanning for a single, specific CVE may be provisioned in OpenAEV if
two conditions are met:

* A scan for the CVE is supported by a Nuclei template (part of the Nuclei distribution),
* A vulnerability taxonomy entry exists in OpenAEV for that same CVE (under Settings > Taxonomies > Vulnerabilities).

These CVE-specific contracts are set up out of the box to use the Nuclei template (with the `-t` argument)
relevant to the CVE.

### Target Selection

Targets are selected based on the `target_selector` field.

#### If target type is **Assets**:

| Selected Property | Uses Asset Field           |
|-------------------|----------------------------|
| Seen IP           | endpoint_seen_ip           |
| Local IP          | First IP from endpoint_ips |
| Hostname          | endpoint_hostname          |

#### If target type is **Manual**:

Direct comma-separated values of IPs or hostnames are used.

### Example Execution

A sample command executed by this injector might look like:

```bash
nuclei -u 192.168.1.10 -tags xss
```
Or with a specific template:
```bash
nuclei -u 10.0.0.5 -t cves/2021/CVE-2021-1234.yaml -j
```
### Output Parsing
- The injector captures and parses the JSON output of Nuclei, and returns:

- Confirmed findings (if any) with severity and CVE IDs

- Other lines as unstructured output


### Target Selection

The targets vary based on the provided input type:

#### If target type is **Assets**:

| Targeted Property   | Source Property        |
|---------------------|------------------------|
| Seen IP             | Seen IP address        |
| Local IP (first)    | IP Addresses (first)   |
| Hostname            | Hostname               |

#### If target type is **Manual**:

- Hostnames or IP addresses are provided directly as comma-separated values.

### Results

Scan results are categorized into:

- **CVEs** (based on template classifications)
- **Other vulnerabilities** (general issues found)

If no vulnerabilities are detected, the injector will clearly indicate this with a **"Nothing Found"** message.

---

## Resources

* [Nuclei Documentation](https://github.com/projectdiscovery/nuclei)
* [Official Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates)
* http://testphp.vulnweb.com/ is a safe, intentionally vulnerable target provided by Acunetix for security testing purposes
