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

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
|---------------|------------|-----------------------------|-----------|------------------------------------------------------|
| OpenAEV URL   | url        | `OPENAEV_URL`               | Yes       | The URL of the OpenAEV platform.                     |
| OpenAEV Token | token      | `OPENAEV_TOKEN`             | Yes       | The default admin token set in the OpenAEV platform. |

### Base injector environment variables

Below are the parameters you'll need to set for running the injector properly:

| Parameter      | config.yml | Docker environment variable | Default | Mandatory | Description                                                                            |
|----------------|------------|-----------------------------|---------|-----------|----------------------------------------------------------------------------------------|
| Injector ID    | id         | `INJECTOR_ID`               | /       | Yes       | A unique `UUIDv4` identifier for this injector instance.                               |
| Collector Name | name       | `INJECTOR_NAME`             |         | Yes       | Name of the injector.                                                                  |
| Log Level      | log_level  | `INJECTOR_LOG_LEVEL`        | info    | Yes       | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`. |

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

### Manual Deployment

#### Prerequisites

The `nmap` and `jc` commands must be installed and available on the system you are running.

#### Configuration

Create a file `config.yml` based on the provided `config.yml.sample`.

Replace the configuration variables with the appropriate configurations for
you environment.

Install the required python dependencies (preferably in a virtual environment):

```shell
pip3 install -r requirements.txt
```

Then, start the injector:

```shell
cd src
python3 openaev_nmap.py
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
