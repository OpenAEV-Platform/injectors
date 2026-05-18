# OpenAEV Nmap Injector

Table of Contents

- [OpenAEV Nmap Injector](#openaev-nmap-injector)
    - [Prerequisites](#prerequisites)
    - [Configuration variables](#configuration-variables)
        - [OpenAEV environment variables](#openaev-environment-variables)
        - [Base injector environment variables](#base-injector-environment-variables)
    - [Deployment](#deployment)
        - [Docker Deployment](#docker-deployment)
        - [Manual Deployment](#manual-deployment)
    - [Behavior](#behavior)

## Prerequisites

Injectors are reaching RabbitMQ based the RabbitMQ configuration provided by the OpenAEV platform. The
injector must be able to reach RabbitMQ on the specified hostname and port.

## Configuration variables

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or
in `config.yml` (for manual deployment).

### OpenAEV environment variables

Below are the parameters you'll need to set for OpenAEV:

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

Below are the parameters you'll need to set for running the injector properly:

| Parameter      | config.yml | Docker environment variable | Default | Mandatory | Description                                                                            |
|----------------|------------|-----------------------------|---------|-----------|----------------------------------------------------------------------------------------|
| Injector ID    | id         | `INJECTOR_ID`               | /       | Yes       | A unique `UUIDv4` identifier for this injector instance.                               |
| Collector Name | name       | `INJECTOR_NAME`             | Nmap    | Yes       | Name of the injector.                                                                  |
| Log Level      | log_level  | `INJECTOR_LOG_LEVEL`        | error   | Yes       | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`. |

## Deployment

### Docker Deployment

Build a Docker Image using the provided `Dockerfile`.

Example:

```shell
# Replace the IMAGE NAME with the appropriate value
docker build --build-context injector_common=../injector_common . -t [IMAGE NAME]:latest
```

Make sure to replace the environment variables in `docker-compose.yml` with the appropriate configurations for your
environment. Then, start the docker container with the provided docker-compose.yml

```shell
docker compose up -d
# -d for detached
```

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

The `nmap` and `jc` commands must be installed and available on the system you are running.

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
poetry run python -m nmap.openaev_nmap
```


## Behavior

The injector enables new inject contracts, supporting the following Nmap scan types:

### Nmap - FIN Scan

Command executed:

```shell
nmap -Pn -sF
```

### Nmap - SYN Scan

Command executed:

```shell
nmap -Pn -sS
```

### Nmap - TCP Connect Scan

Command executed:

```shell
nmap -Pn -sT
```

### Target Selection

The targets vary based on the provided options:

If type of targets is Assets:

| Targeted property | Asset property       | 
|-------------------|----------------------|
| Seen IP           | Seen IP address      |
| Local IP (first)  | IP Addresses (first) |
| Hostname          | Hostname             |

If type of targets is Manual:

- Hostnames or IP addresses are provided directly as comma-separated values.

### Resources

- Official Nmap Documentation: https://nmap.org/docs.html
- Options Explanation:
    - -Pn: Host Discovery
    - -sS: SYN Scan
    - -sT: TCP Connect Scan
    - -sF: FIN Scan
