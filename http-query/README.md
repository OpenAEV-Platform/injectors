# OpenAEV Http Query Injector

Table of Contents

- [OpenAEV Http Query Injector](#openaev-http-query-injector)
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

| Parameter        | config.yml | Docker environment variable | Default | Mandatory | Description                                                                            |
|------------------|------------|-----------------------------|---------|-----------|----------------------------------------------------------------------------------------|
| Injector ID      | id         | `INJECTOR_ID`               | /       | Yes       | A unique `UUIDv4` identifier for this injector instance.                               |
| Collector Name   | name       | `INJECTOR_NAME`             |         | Yes       | Name of the injector.                                                                  |
| Log Level        | log_level  | `INJECTOR_LOG_LEVEL`        | info    | Yes       | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`. |

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

Create a file `config.yml` based on the provided `config.yml.sample`.

Replace the configuration variables with the appropriate configurations for
you environment.

The poetry package management system (version 2.1 or later) must also be available: https://python-poetry.org/

Install the environment:

**Production**:
```shell
# production environment
poetry install --extras prod
```

**Development** (note that you should also clone the [pyoaev](OpenAEV-Platform/client-python) repository [according to
these instructions](../README.md#simultaneous-development-on-pyoaev-and-an-injector))
```shell
# development environment
poetry install --extras dev
```

Then, start the collector:

```shell
poetry run python -m http_query.openaev_http
```


## Behavior

This injector enables new inject contracts, allowing for API calls of the Get, Post, and Put types.

### Passing headers with the request
The contracts created in OpenAEV include an optional "Headers" parameter. While this field is technically a free-form
text input, the contents passed to it are expected to be in a certain format: `key=value` and together separated with a comma  `,`.

Note the pattern supports whitespace within the keys and values.

Example:
```plaintext
content-type=application/json,x-custom-header=value for the header
```