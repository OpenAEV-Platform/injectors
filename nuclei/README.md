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

| Parameter          | config.yml | Docker environment variable | Mandatory | Description                                           |
|--------------------|------------|-----------------------------|-----------|-------------------------------------------------------|
| OpenAEV URL        | url        | `OPENAEV_URL`               | Yes       | The URL of the OpenAEV platform.                      |
| OpenAEV Token      | token      | `OPENAEV_TOKEN`             | Yes       | The default admin token set in the OpenAEV platform.  |
| OpenAEV Tenant ID  | tenant_id  | `OPENAEV_TENANT_ID`         | No        | Identifier of the tenant within the OpenAEV platform. |

> ⚠️ Warning ⚠️
>
> The `tenant_id` parameter is a new configuration option. A period of backward compatibility is ensured: if this key is not defined,
> existing configurations will not be affected, and the default value will be `None`. However, if a value is provided, it will be
> validated by Pydantic and must conform to a valid UUID format, otherwise, a validation error will be returned.

### Base injector environment variables

| Parameter                               | config.yml                                                 | Docker environment variable                                | Default | Mandatory | Description                                                                                         |
|-----------------------------------------|------------------------------------------------------------|------------------------------------------------------------|---------|-----------|-----------------------------------------------------------------------------------------------------|
| Injector ID                             | `injector.id`                                              | `INJECTOR_ID`                                              | /       | Yes       | A unique `UUIDv4` identifier for this injector instance.                                            |
| Injector Name                           | `injector.name`                                            | `INJECTOR_NAME`                                            |         | Yes       | Name of the injector.                                                                               |
| Log Level                               | `injector.log_level`                                       | `INJECTOR_LOG_LEVEL`                                       | info    | Yes       | Determines the verbosity of the logs. Options: `debug`, `info`, `warn`, or `error`.                 |
| External contracts maintenance schedule | `injector.external_contracts_maintenance_schedule_seconds` | `INJECTOR_EXTERNAL_CONTRACTS_MAINTENANCE_SCHEDULE_SECONDS` | 86400   | No        | With every tick, trigger a maintenance of the external contracts (e.g. based on Nuclei templates)   |

---

### Nuclei environment variables

| Parameter                              | config.yml                              | Docker environment variable             | Default      | Mandatory | Description                                                                                          |
|----------------------------------------|-----------------------------------------|-----------------------------------------|--------------|-----------|------------------------------------------------------------------------------------------------------|
| Nuclei Scan Strategy                   | `nuclei.scan_strategy`                  | `NUCLEI_SCAN_STRATEGY`                  | `host-spray` | No        | Strategy to use while scanning (auto, host-spray, template-spray). Nuclei Flags: -ss, -scan-strategy |
| Nuclei Templates Parallelism           | `nuclei.templates_parallelism`          | `NUCLEI_TEMPLATES_PARALLELISM`          | `5`          | No        | Maximum number of templates to be executed in parallel. Nuclei Flags: -c, -concurrency               |
| Nuclei Hosts parallelism per templates | `nuclei.hosts_parallelism_per_template` | `NUCLEI_HOSTS_PARALLELISM_PER_TEMPLATE` | `5`          | No        | Maximum number of hosts to be analyzed in parallel per template. Nuclei Flags: -bs, -bulk-size       |
| Nuclei Max requests per second         | `nuclei.max_requests_per_second`        | `NUCLEI_MAX_REQUESTS_PER_SECOND`        | `50`         | No        | Maximum number of requests to send per second. Nuclei Flags: -rl, -rate-limit                        |
| Nuclei Timeout                         | `nuclei.timeout`                        | `NUCLEI_TIMEOUT`                        | `10`         | No        | Time to wait in seconds before timeout. Nuclei Flags: -timeout                                       |
| Nuclei Retries                         | `nuclei.retries`                        | `NUCLEI_RETRIES`                        | `1`          | No        | Number of times to retry a failed request. Nuclei Flags: -retries                                    |
| Nuclei Max host error                  | `nuclei.max_host_error`                 | `NUCLEI_MAX_HOST_ERROR`                 | `30`         | No        | Max errors for a host before skipping from scan. Nuclei Flags: -mhe, -max-host-error                 |
| Nuclei response size read              | `nuclei.response_size_read`             | `NUCLEI_RESPONSE_SIZE_READ`             | `1048576`    | No        | Max response size to read in bytes. Nuclei Flags: -rsr, -response-size-read                          |
| Nuclei response size save              | `nuclei.response_size_save`             | `NUCLEI_RESPONSE_SIZE_SAVE`             | `1048576`    | No        | Max response size to save in bytes. Nuclei Flags: -rss, -response-size-save                          |
| Nuclei exclude type                    | `nuclei.exclude_type`                   | `NUCLEI_EXCLUDE_TYPE`                   | `headless`   | No        | Templates to exclude based on protocol type (comma-separated). Nuclei Flags: -ept, -exclude-type     |
| Nuclei exclude severity                | `nuclei.exclude_severity`               | `NUCLEI_EXCLUDE_SEVERITY`               | /            | No        | Templates to exclude based on severity (comma-separated). Nuclei Flags: -es, -exclude-severity       |

#### Nuclei Resource Management

> [!IMPORTANT]
> 
> To ensure optimal stability, security, and compatibility, Nuclei must be kept up to date. 
> Recommended Nuclei version: v3.8.0

Nuclei is a highly concurrent vulnerability scanner. While this enables fast and scalable scans, it can also lead to 
significant CPU, memory, and network consumption if not properly configured. For this reason, Nuclei injector exposes a 
controlled subset of Nuclei performance and safety parameters that can be adjusted based on infrastructure capacity and 
scanning requirements.

The default injector configuration is intentionally conservative and designed as a safe baseline for containerized 
environments, including Kubernetes clusters with typical memory limits of `256Mi`-`512Mi` per pod.

> [!WARNING]
> 
> If flags and available options are not properly configured, Nuclei can overutilize resources and can cause the 
> following issues:
> - OOM Killed by the system
> - Hangs and crashes
> - Error code 137 etc

Resource consumption scales multiplicatively rather than linearly, meaning that increasing multiple parameters 
simultaneously significantly amplifies memory and CPU usage.

| Parameter                        | Corresponding Flag   | Safe  | Balanced | Fast    |
|----------------------------------|----------------------|-------|----------|---------|
| `templates_parallelism`          | `-c`, `-concurrency` | 5–10  | 10–15    | 15–25   |
| `hosts_parallelism_per_template` | `-bs`, `-bulk-size`  | 5–10  | 10–15    | 15–25   |
| `max_requests_per_second`        | `-rl`, `-rate-limit` | 20–50 | 50–100   | 100–150 |

These parameters are interdependent and must be adjusted together rather than in isolation. They should also be 
adjusted gradually according to the infrastructure capacity and workload characteristics.

Configuration tuning should always take into account the execution context:
- For `single-target` scans, higher concurrency values can be safely used to improve performance.
- For `multi-target` scans, it is recommended to use more conservative settings to avoid resource saturation.

Nuclei configuration requires careful trade-offs, as these parameters directly impact performance, stability, and 
resource consumption.

The following guidelines should be considered:
- Higher safety settings increase scan duration but improve stability.
- `host-spray` is the recommended scan strategy for predictable and stable resource usage.
- `max_host_error` must be greater than `templates_parallelism` and `hosts_parallelism_per_template` to prevent 
premature host exclusion under high concurrency workloads.
- `headless` templates should be used with caution due to their high resource consumption (embedded headless browser 
execution).
- Increasing template exclusions (`exclude_type`, `exclude_severity`) reduces the active template set and improves scan 
performance.

> [!WARNING]
> 
> The `response_size_read` parameter has a direct impact on memory consumption:
> Memory usage is approximately proportional to:
> - 1–1.5 × (`templates_parallelism` × `response_size_read`)
> 
> For this reason, increasing both `templates_parallelism` and `response_size_read` simultaneously can significantly 
> increase memory pressure and lead to `OOM Killed` in constrained environments.

For more information:
- See [Nuclei's documentation on mass scanning](https://docs.projectdiscovery.io/opensource/nuclei/mass-scanning-cli#understanding-how-nuclei-consumes-resources)
- See [Nuclei's documentation on flags](https://docs.projectdiscovery.io/opensource/nuclei/running#nuclei-flags)

## Deployment

### Docker Deployment

Build the Docker image using the provided `Dockerfile`.

```bash
docker build --build-context injector_common=../injector_common .  -t openaev/injector-nuclei:latest
````

Edit the `docker-compose.yml` file with your OpenAEV configuration, then start the container:

```bash
docker compose up -d
```

> ✅ The Docker image **already contains Nuclei**. No further installation is needed inside the container.

---

#### Domain name resolution - Local openAEV with Injector container
**Note:** If you are running OpenAEV locally on your host machine and want to run this injector inside a Docker container, the `openaev` URL defined in `config.yml` and `.env` must be reachable from inside the container.

Inside a container, `localhost` refers to the container itself - not your host machine. Therefore, you cannot use `localhost` as the OpenAEV URL unless OpenAEV is running inside the same container.

Instead, use: `host.docker.internal`. This hostname allows the container to access services running on your host machine.

**In short**:
- `localhost` -> container itself
- `host.docker.internal` -> your host machine

**Platform-specific notes**:
- **macOS / Windows (Docker Desktop):**     
  `host.docker.internal` works out of the box. No additional configuration is needed.
- **Linux:**  
  You must explicitly map it using `extra_hosts`:
```yaml
services:
  your-injector-name:
    image: your-image-name
    extra_hosts:
      - "host.docker.internal:host-gateway"
```

**Important**:
- Avoid mapping `host.docker.internal` to a fixed IP (e.g. `1.2.3.4`) unless you have a specific reason. The host IP can change, and Docker provides `host-gateway` to handle this dynamically.
- Make sure your OpenAEV service is listening on `0.0.0.0` (not just `localhost`), otherwise it may NOT be accessible from the container.

---

### Manual Deployment

#### Prerequisites

* **Nuclei must be installed locally** and accessible via the command line (`nuclei` command).
* You can install it from: [https://github.com/projectdiscovery/nuclei#installation](https://github.com/projectdiscovery/nuclei#installation)

The poetry package management system (version 2.1 or later) must also be available: https://python-poetry.org/
Install the environment:

**Production**:
```shell
# production environment
poetry install 
```

**Development** (note that you should also clone the [pyoaev](OpenAEV-Platform/client-python) repository [according to
these instructions](../README.md#simultaneous-development-on-pyoaev-and-an-injector))
```shell
# development environment
poetry install --extras dev
```

Then, start the collector:

```shell
poetry run python -m nuclei.openaev_nuclei
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

### Options

You can add any options you want based on what is available for nuclei

### Example Execution

A sample command executed by this injector might look like:

```bash
nuclei -u 192.168.1.10 -tags xss
```
Or with a specific template:
```bash
nuclei -u 10.0.0.5 -t cves/2021/CVE-2021-1234.yaml -j
```
Or with options:
```bash
nuclei -u https://www.google.com -t dast/vulnerabilities/sqli/sqli-error-based.yaml -dast
```

### Output Parsing
- The injector captures and parses the JSON output of Nuclei, and returns:

- Confirmed findings (if any) with severity and CVE IDs

- Other lines as unstructured output

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
