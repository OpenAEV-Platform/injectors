# OpenBAS Nuclei Injector

## Table of Contents

- [OpenBAS Nuclei Injector](#openbas-nuclei-injector)
  - [Prerequisites](#prerequisites)
  - [Configuration variables](#configuration-variables)
    - [OpenBAS environment variables](#openbas-environment-variables)
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

- It **must be able to reach the OpenBAS platform** via the URL you provide (through `OPENBAS_URL` or `config.yml`).
- It **must be able to reach the RabbitMQ broker** used by the OpenBAS platform.

---

## Configuration variables

Configuration is provided either through environment variables (Docker) or a config file (`config.yml`, manual).

### OpenBAS environment variables

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
|---------------|------------|-----------------------------|-----------|------------------------------------------------------|
| OpenBAS URL   | url        | `OPENBAS_URL`               | Yes       | The URL of the OpenBAS platform.                     |
| OpenBAS Token | token      | `OPENBAS_TOKEN`             | Yes       | The default admin token set in the OpenBAS platform. |

### Base injector environment variables

| Parameter      | config.yml | Docker environment variable | Default | Mandatory | Description                                                                            |
|----------------|------------|-----------------------------|---------|-----------|----------------------------------------------------------------------------------------|
| Injector ID    | id         | `INJECTOR_ID`               | /       | Yes       | A unique `UUIDv4` identifier for this injector instance.                               |
| Injector Name  | name       | `INJECTOR_NAME`             |         | Yes       | Name of the injector.                                                                  |
| Log Level      | log_level  | `INJECTOR_LOG_LEVEL`        | info    | Yes       | Determines the verbosity of the logs. Options: `debug`, `info`, `warn`, or `error`.   |

---

## Deployment

### Docker Deployment

Build the Docker image using the provided `Dockerfile`.

```bash
docker build . -t openbas/injector-nuclei:latest
````

Edit the `docker-compose.yml` file with your OpenBAS configuration, then start the container:

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

1. Copy `config.yml.sample` to `config.yml` and edit the relevant values.
2. Install Python dependencies (ideally in a virtual environment):

```bash
pip3 install -r src/requirements.txt
```

3. Run the injector:

```bash
cd src
python3 openbas_nuclei.py
```

---

## Behavior

The Nuclei injector supports contract-based scans by dynamically constructing and executing Nuclei commands based on provided tags or templates.

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

### Target Selection

Targets are selected based on the `target_selector` field.

#### If target type is **Assets**:

| Selected Property | Uses Asset Field         |
|-------------------|-------------------------|
| Seen IP           | endpoint_seen_ip         |
| Local IP          | First IP from endpoint_ips |
| Hostname          | endpoint_hostname       |

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
