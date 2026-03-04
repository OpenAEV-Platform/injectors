# OpenAEV Shodan Injector

## Table of Contents

- [OpenAEV SHODAN Injector](#openaev-shodan-injector)
    - [Prerequisites](#prerequisites)
    - [Configuration variables](#configuration-variables)
        - [Base OpenAEV environment variables](#base-openaev-environment-variables)
        - [Base injector environment variables](#base-injector-environment-variables)
        - [Base Shodan environment variables](#base-shodan-environment-variables)
    - [Deployment](#deployment)
        - [Docker Deployment](#docker-deployment)
        - [Manual Deployment](#manual-deployment)
    - [Behavior](#behavior)
    - [Supported Contracts](#supported-contracts)
        - [Fields available in manual mode by contract](#fields-available-in-manual-mode-by-contract)
        - [Output Trace Message](#output-trace-message)
        - [Auto-Create Assets](#auto-create-assets)
        - [Rate Limiting and Retry](#rate-limiting-and-retry)
    - [Resources](#resources)

---

## Prerequisites

This injector uses [Shodan](https://www.shodan.io/) to collect information about exposed assets.

To operate correctly, the injector requires:

- A **valid Shodan API key**, which must be provided through an environment variable (`SHODAN_API_KEY`) or via the `config.yml` file.
- You can create an account on this page: https://account.shodan.io/register

In addition, for proper integration with the OpenAEV platform:

- It **must be able to reach the OpenAEV platform** via the URL you provide (through `OPENAEV_URL` or `config.yml`).
- It **must be able to reach the RabbitMQ broker** used by the OpenAEV platform.

Depending on your deployment method:

- When using the **Docker deployment**, ensure the Shodan API key is correctly injected into the container environment.
- When running manually (e.g., in development), the Shodan API key must be available in your local environment.

---

## Configuration variables

Configuration is provided either through environment variables (Docker) or a config
file (`config.yml`, manual).

---

### Base OpenAEV environment variables

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
|---------------|------------|-----------------------------|-----------|------------------------------------------------------|
| OpenAEV URL   | url        | `OPENAEV_URL`               | Yes       | The URL of the OpenAEV platform.                     |
| OpenAEV Token | token      | `OPENAEV_TOKEN`             | Yes       | The default admin token set in the OpenAEV platform. |

### Base injector environment variables

| Parameter     | config.yml  | Docker environment variable  | Default          | Mandatory | Description                                                                            |
|---------------|-------------|------------------------------|------------------|-----------|----------------------------------------------------------------------------------------|
| Injector ID   | id          | `INJECTOR_ID`                | `shodan--<uuid>` | No        | A unique `UUIDv4` identifier for this injector instance.                               |
| Injector Name | name        | `INJECTOR_NAME`              | `Shodan`         | No        | Name of the injector.                                                                  |
| Log Level     | log_level   | `INJECTOR_LOG_LEVEL`         | `error`          | No        | Determines the verbosity of the logs. Options: `debug`, `info`, `warning`, or `error`. |


### Base Shodan environment variables

| Parameter                        | config.yml                | Docker environment variable        | Default                 | Mandatory | Description                                                                                                                                                                                    |
|----------------------------------|---------------------------|------------------------------------|-------------------------|-----------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Shodan Base URL                  | token                     | `SHODAN_BASE_URL`                  | `https://api.shodan.io` | No        | This is the base URL for the Shodan API.                                                                                                                                                       |
| Shodan API Key                   | api_key                   | `SHODAN_API_KEY`                   | /                       | Yes       | This is the API key for the Shodan API.                                                                                                                                                        |
| Shodan API leaky bucket rate     | api_leaky_bucket_rate     | `SHODAN_API_LEAKY_BUCKET_RATE`     | `10`                    | No        | Bucket refill rate (in tokens per second). Controls the rate at which API calls are allowed. For example, a rate of 10 means that 10 calls can be made per second, if the bucket is not empty. |
| Shodan API leaky bucket capacity | api_leaky_bucket_capacity | `SHODAN_API_LEAKY_BUCKET_CAPACITY` | `10`                    | No        | Maximum bucket capacity (in tokens). Defines the number of calls that can be made immediately in a burst. Once the bucket is empty, it refills at the rate defined by 'api_leaky_bucket_rate'. |
| Shodan API Retry                 | api_retry                 | `SHODAN_API_RETRY`                 | `5`                     | No        | Maximum number of attempts (including the initial request) in case of API failure.                                                                                                             |
| Shodan API backoff               | api_backoff               | `SHODAN_API_BACKOFF`               | `PT30S`                 | No        | Maximum exponential backoff delay between retry attempts (ISO 8601 duration format).                                                                                                           |

---

## Deployment

---

### Docker Deployment

Build the Docker image using the provided `Dockerfile`:

```bash
docker build --build-context injector_common=../injector_common . -t openaev/injector-shodan:latest
```

Edit the `docker-compose.yml` file with your OpenAEV configuration, then start the container:

```bash
docker compose up -d
```

> ✅ The Docker image already includes the Shodan injector and its runtime dependencies.  
Only a valid `SHODAN_API_KEY` and access to the OpenAEV platform are required at runtime.

---

### Manual Deployment

This injector can be run manually in different modes, depending on whether you want **production**, **current**, or **development/testing**.

---

#### Prerequisites

- Python 3.11+ installed
- Poetry installed (https://python-poetry.org/) / uv / pip
- A valid `SHODAN_API_KEY` set as environment variable or in `config.yml`
- Access to the OpenAEV platform (`OPENAEV_URL` / `OPENAEV_TOKEN`) and RabbitMQ


#### Install and Run with Pip

Use pip if you prefer a classic Python workflow or for **development/testing with local dependencies**.

```bash
# Create a virtual environment
python -m venv .venv

# Activate the venv 
# Linux / macOS
source .venv/bin/activate
# Windows - Git Bash
source .venv/Scripts/activate

# Install prod dependencies (stable Pyoaev release)
pip install .[prod]

# Install current release from Git / latest
pip install .[current]

# Install dependencies (Dev + Test includes local client-python)
pip install -r requirements.txt
```

Run the injector:
The injector can be started using either the Python module or the console entry point, depending on how it was installed.

Run as a Python module (recommended for Docker and simple setups)
```bash
python -m shodan
```

Run using the console entry point
```bash
# Requires the package to be installed and the virtual environment to be active
ShodanInjector
```

**Why use pip:**

- Manages local modifiable dependencies (`../../client-python`) that Poetry cannot resolve automatically while complying with PEP.
- Handles extras and entry points (ShodanInjector) defined in `pyproject.toml`
- Installs development/test extras (`.[dev,test]`) in a Poetry-compatible venv.

#### Install and Run with Poetry
Use Poetry for production or current releases, or to manage dependencies automatically in an isolated virtual environment.

```bash
# Install prod dependencies (stable Pyoaev release)
poetry install --extras prod

# Install current release from Git / latest
poetry install --extras current

# Tips For development/testing with local Pyoaev (client-python)
poetry run pip install -r requirements.txt
```

Run the injector:
```bash
poetry run ShodanInjector
```

Run using the console entry point
```bash
# Requires the package to be installed and the virtual environment to be active
ShodanInjector
```

**Why use Poetry:**

- Automatically creates and manages a virtual environment
- Handles extras and entry points (ShodanInjector) defined in `pyproject.toml`
- Keeps your environment isolated and PEP 621 compliant

#### Commands Summary:
The table below summarizes the installation and run commands for different workflows (pip or Poetry, prod/current/dev).

| Installation    | Install Command                              | Run Command                                                           | Notes                                                    |
|-----------------|----------------------------------------------|-----------------------------------------------------------------------|----------------------------------------------------------|
| Pip Prod        | `pip install .[prod]`                        | `python -m shodan` / `ShodanInjector` (Requires venv active)          | Installs stable dependencies, venv managed automatically |
| Pip Current     | `pip install .[current]`                     | `python -m shodan` / `ShodanInjector` (Requires venv active)          | Installs latest release from Git                         |
| Pip Dev/Test    | `pip install -r requirements.txt`            | `python -m shodan` / `ShodanInjector` (Requires venv active)          | Handles local editable client-python + dev/test extras   |
| Poetry Prod     | `poetry install --extras prod`               | `poetry run ShodanInjector` / `ShodanInjector` (Requires venv active) | Installs stable dependencies, venv managed automatically |
| Poetry Current  | `poetry install --extras current`            | `poetry run ShodanInjector` / `ShodanInjector` (Requires venv active) | Installs latest release from Git                         |
| Poetry Dev/Test | `poetry run pip install -r requirements.txt` | `poetry run ShodanInjector` / `ShodanInjector` (Requires venv active) | Handles local editable client-python + dev/test extras   |

---

## Behavior

For the Shodan injector, we have 7 contracts available.

- Specific behavior for all contracts:
    - For each contract that has the hostnames and organization fields
        - For each hostname entered in the hostname field, a dedicated API call will be made with its associated wildcard.
            - Example: `hostname:filigran.io,*.filigran.io` (wildcard)
        - If left empty, the organization is automatically derived from each hostname. Otherwise, the specified organization is applied to all hostnames.
    - Once all calls have been made, a final API call is made to retrieve user information, including the remaining quota.

### Supported Contracts

- Cloud Provider Asset Discovery
- Critical Ports And Exposed Admin Interface
- Custom Query
- CVE Enumeration
- CVE Specific Watchlist (The only contract that requires a plan Shodan only available to academic users, Small Business API subscribers, and higher.)
- Domain Discovery
- IP Enumeration

### Target Selection

Targets are selected based on the `target_selector` field.

#### If target type is **Assets** / **Asset-Groups**: (Currently disabled)

| Selected Property | Uses Asset Field           |
|-------------------|----------------------------|
| Automatic         | Automatic                  |
| Seen IP           | endpoint_seen_ip           |
| Local IP          | First IP from endpoint_ips |
| Hostname          | endpoint_hostname          |

#### If target type is **Manual**:

Direct values separated by commas or spaces between IP addresses or hostnames are used.

### Fields available in manual mode by contract

- Cloud Provider Asset Discovery (Search Shodan Endpoint: `/shodan/host/search`)
    - The `Cloud Provider` field must contain one or more cloud providers, separated by commas.
    - The `Hostname` field must contain one or more hostnames, separated by commas.
    - The `Organization` field must contain one or more organizations, separated by commas.

    | Field          | Mandatory | Default / Notes                       |
    |----------------|-----------|---------------------------------------|
    | Cloud Provider | Yes       | `Google,Microsoft,Amazon,Azure`       |
    | Hostname       | Yes       | /                                     |
    | Organization   | No        | If empty, the hostname value is used. |

- Critical Ports And Exposed Admin Interface (Search Shodan Endpoint: `/shodan/host/search`)
    - The `Port` field must contain one or more ports, separated by commas.
    - The `Hostname` field must contain one or more hostnames, separated by commas.
    - The `Organization` field must contain one or more organizations, separated by commas.
    
    | Field        | Mandatory   | Default / Notes                                                                     |
    |--------------|-------------|-------------------------------------------------------------------------------------|
    | Port         | Yes         | `20,21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080` |
    | Hostname     | Yes         | /                                                                                   |
    | Organization | No          | If empty, the hostname value is used.                                               |

- Custom Query (Search Shodan Endpoint: `/shodan/host/search` + your custom query)
    - You can find all available filters here: https://beta.shodan.io/search/filters
    -  Note that spaces and commas are important. You must use the same formatting as in the Shodan search bar.
      - `Spaces = AND` / `Commas = OR`

    | Field        | Mandatory | Default / Notes                         |
    |--------------|-----------|-----------------------------------------|
    | Custom Query | Yes       | /                                       |

- CVE Enumeration (Search Shodan Endpoint: `/shodan/host/search`)
    - The `Hostname` field must contain one or more hostnames, separated by commas.
    - The `Organization` field must contain one or more organizations, separated by commas.
  
    | Field        | Mandatory | Default / Notes                       |
    |--------------|-----------|---------------------------------------|
    | Hostname     | Yes       | /                                     |
    | Organization | No        | If empty, the hostname value is used. |

- CVE Specific Watchlist (Search Shodan Endpoint: `/shodan/host/search`)
    - Warning : The only contract that requires a plan Shodan only available to academic users, Small Business API subscribers, and higher.
    - The `Vulnerability` field must contain one or more specific CVEs.
    - The `Hostname` field must contain one or more hostnames, separated by commas.
    - The `Organization` field must contain one or more organizations, separated by commas.

    | Field         | Mandatory | Default / Notes                       |
    |---------------|-----------|---------------------------------------|
    | Vulnerability | Yes       | /                                     |                           
    | Hostname      | Yes       | /                                     |                           
    | Organization  | No        | If empty, the hostname value is used. |                        

- Domain Discovery (Search Shodan Endpoint: `/shodan/host/search`)
    - The `Hostname` field must contain one or more hostnames, separated by commas.
    - The `Organization` field must contain one or more organizations, separated by commas.

    | Field        | Mandatory | Default / Notes                       |
    |--------------|-----------|---------------------------------------|
    | Hostname     | Yes       | /                                     | 
    | Organization | No        | If empty, the hostname value is used. |

- IP Enumeration (Search Shodan Endpoint: `/shodan/host/search`)
    - The `IP` field must contain one or more valid IPv4 addresses.
     
    | Field | Mandatory | Default / Notes |
    |-------|-----------|-----------------|
    | IP    | Yes       | /               | 

---

### Output Trace Message
The injector captures the fields filled in by the user and analyzes the JSON output of the Shodan response, 
then returns several sections in the report if successful:

- **Section Title** – Contains the title of the report and the date and time it was created.
- **Section Config** – Groups all the configuration information entered by the user for the current contract.
- **Section Info** – Makes an additional final call to the Shodan API to determine the user's remaining quota and plan.
- **Section External API** – Processes information from Shodan API responses based on the contract and fields filled in. This section also includes:
  - Call Success – List of successful calls + As well as various other relevant information related to API calls.
  - Call Failed – List of failed calls + As well as various other relevant information related to API calls.
- **Section Table** – Visually displays the details of each call, based on the configuration defined for the contract in the injector.
- **Section JSON** – JSON return of the response directly (In the case of a "custom query", we return the JSON directly rather than the table section.)

### Auto-Create Assets
- Feature currently under development

### Rate Limiting and Retry

#### Overview

The Shodan API does not publicly document strict rate-limiting rules or request thresholds.
However, to ensure stable and reliable interactions with the API, a rate-limiting and retry mechanism is implemented.

These mechanisms aim to:
- Smooth the flow of outgoing requests,
- Reduce the risk of HTTP 429 Too Many Requests responses,
- Handle transient failures,
- Improve the clarity of error reporting in output traces message.

#### Rate limiting 

A rate-limiting mechanism is applied to control the frequency of API calls.
Requests are deliberately paced to avoid sending bursts of traffic that could exceed Shodan’s internal limits or trigger protective measures.

This approach helps:
- Prevent temporary blocking or throttling,
- Ensure consistent behavior across multiple API calls,
- Maintain predictable execution when processing multiple hostnames or IPs.

There are two environment variables for controlling the flow:
- `SHODAN_API_LEAKY_BUCKET_RATE` - Controls the rate at which API requests are allowed to be executed.
- `SHODAN_API_LEAKY_BUCKET_CAPACITY` - Defines the maximum burst size allowed before requests are delayed.

#### Retry strategy

A retry mechanism is applied to handle failed API requests.
Requests are retried after a short delay to mitigate transient failures and improve execution stability.

This approach helps:
- Automatically retry failed requests up to a limited number of attempts.
- Introduce delays between retries to avoid repeated immediate failures.

There are two environment variables for controlling the flow:
- `SHODAN_API_RETRY` - Defines the maximum number of retry attempts for a failed request.
- `SHODAN_API_BACKOFF` - Specifies the maximum delay (in seconds) applied between retry attempts, using an exponential backoff strategy.

#### Execution trace and feedback

Each API call is tracked individually.
The success or failure of each request is reported in the external API section of the output trace message.

Once all API calls related to the host name or IP address have been made, a final API call is executed to retrieve user information, including the remaining API quota.

---

## Resources

**Filigran**
- Homepage: https://filigran.io/
- Repository: https://github.com/OpenAEV-Platform/injectors/tree/main/shodan
- Documentation: https://github.com/OpenAEV-Platform/injectors/tree/main/shodan/README.md
- Issues: https://github.com/OpenAEV-Platform/injectors/issues

**Shodan**
- Homepage: https://www.shodan.io/
- Register Page: https://account.shodan.io/register
- REST API Documentation: https://developer.shodan.io/api