# Common Implementation Guidelines

> **Applicable to:** all inject types
> **Part of:** [OpenAEV Injector Documentation](../../CONTRIBUTING.md)

This document describes implementation patterns shared by **all** `OpenAEV` injectors, regardless of the inject type they handle. Read this before diving into the inject-type-specific guide.

> ⚠️ Important
>
> This document is subject to change. We are currently working on a standardized template for injectors.

---

## Table of Contents

- [Injector Structure](#injector-structure)
- [Entry Point](#entry-point)
- [Contract Definition](#contract-definition)
- [Configuration](#configuration)
    - [Pydantic BaseSettings](#pydantic-basesettings)
    - [Environment Variables](#environment-variables)
    - [Secrets Management](#secrets-management)
- [Platform Communication via pyoaev](#platform-communication-via-pyoaev)
- [Logging](#logging)
- [Error Handling](#error-handling)
- [Result Reporting](#result-reporting)
- [Local Development Setup](#local-development-setup)
- [Testing](#testing)
- [Docker Packaging](#docker-packaging)

---

## Injector Structure

All injectors follow the modular layout established by the Shodan injector:

```
my_injector/
├── my_injector/
│   ├── __init__.py
│   ├── __main__.py
│   ├── contracts/
│   │   ├── __init__.py
│   │   ├── my_contracts.py
│   │   ├── contract_a/
│   │   │   ├── __init__.py
│   │   │   └── contract.py
│   │   └── contract_b/
│   │       ├── __init__.py
│   │       └── contract.py
│   └── img/
│   │   └── icon-my-injector.png
│   ├── injector/
│   │   ├── __init__.py
│   │   └── openaev_my_injector.py
│   ├── models/
│   │   ├── __init__.py
│   │   ├── configs/
│   │   │   ├── config_loader.py
│   │   │   ├── injector_config_override.py
│   │   │   └── my_injector_configs.py
│   │   └── ...
│   ├── services/
│   │   ├── __init__.py
│   │   ├── client_api.py
│   │   └── utils.py
├── tests/
│   ├── __init__.py
│   ├── conftest.py
│   └── my_injector_contracts/
│      ├── constraints/
│      │   ├── myconstraint.constraint.feature
│      │   └── test_myconstraint.py
│      ├── contract_a/
│      │   ├── contract_a.feature
│      │   └── test_contract_a.py
│      └── contract_b/
│          ├── contract_b.feature
│          └── test_contract_b.py
├── .dockerignore
├── .env.sample
├── .gitignore
├── config.yml.sample
├── CONTRIBUTING.md
├── docker-compose.yml
├── Dockerfile
├── manifest-metadata.json
├── pyproject.toml
└── README.md
```

Each injector is an **independent process**: it has its own dependencies, its own Docker image, and communicates with the platform exclusively via `pyoaev`.

---

## Entry Point

`my_injector/__main__.py` is the single entry point, registered as a console script in `pyproject.toml`:

```toml
[project.scripts]
MyInjector = "my_injector.__main__:main"
```

The `main()` function has a fixed structure:

```python
"""Main entry point for the injector."""

import logging
import os
import sys
from pathlib import Path

from pydantic import ValidationError
from pyoaev.helpers import OpenAEVConfigHelper, OpenAEVInjectorHelper

from injector_common.dump_config import intercept_dump_argument
from my_injector.injector.openaev_my_injector import MyInjector
from my_injector.models import ConfigLoader

LOG_PREFIX = "[MY_INJECTOR_MAIN]"

def main() -> None:
    logger = logging.getLogger(__name__)
    try:
        config = ConfigLoader()
        intercept_dump_argument(config.to_daemon_config())

        icon_bytes = (
            Path(__file__).parents[1] / config.injector.icon_filepath
        ).read_bytes()

        helper = OpenAEVInjectorHelper(
            config=OpenAEVConfigHelper.from_configuration_object(
                config.to_daemon_config()
            ),
            icon=icon_bytes,
        )
        
        logger.info(f"{LOG_PREFIX} Configuration initialized successfully.")
        injector = MyInjector(config, helper)
        injector.start()

    except ValidationError as err:
        logger.error(f"{LOG_PREFIX} Configuration error: {err}")
        sys.exit(2)

    except KeyboardInterrupt:
        logger.info(f"{LOG_PREFIX} Stopped by user (Ctrl+C)")
        os._exit(0)

    except Exception as err:
        logger.exception(f"{LOG_PREFIX} Fatal error: {err}")
        sys.exit(1)

if __name__ == "__main__":
    main()
```

The pyoaev library abstracts transport-level concerns including:
- RabbitMQ connectivity
- message consumption and acknowledgement
- reconnection handling
- injector runtime lifecycle

Injector authors should focus exclusively on business-specific execution logic implemented in `process_message()` 
and `start()`.

---

## Contract Definition

Each contract is defined in its own subdirectory as a class with three static methods:

```python
# contracts/operation_a/contract.py

class OperationA:
    @staticmethod
    def output_trace_config() -> dict:
        """Rendering configuration for the output message displayed in OpenAEV."""
        return { ... }

    @classmethod
    def contract_with_specific_fields(
        cls,
        base_fields: list[ContractElement],
        source_selector_key: str,
        target_selector_field: type["TargetSelectorField"],
    ) -> list[ContractElement]:
        """Add contract-specific fields on top of the shared base fields."""
        specific_fields = [
            ContractText(key="my_param", label="My Parameter", mandatory=True, ...),
        ]
        return ContractBuilder().add_fields(base_fields + specific_fields).build_fields()

    @staticmethod
    def contract_with_specific_outputs(
        base_outputs: list[ContractOutputElement],
    ) -> list[ContractOutputElement]:
        """Define contract-specific output elements."""
        return ContractBuilder().add_outputs(base_outputs).build_outputs()

    @staticmethod
    def contract(
        contract_id: str,
        contract_config: ContractConfig,
        contract_with_specific_fields: list[ContractElement],
        contract_with_specific_outputs: list[ContractOutputElement],
    ) -> Contract:
        return Contract(
            contract_id=contract_id,
            config=contract_config,
            label={
                SupportedLanguage.en: "My Injector - Operation A",
                SupportedLanguage.fr: "Mon Injecteur - Opération A",
            },
            fields=contract_with_specific_fields,
            outputs=contract_with_specific_outputs,
            manual=False,
        )
```

The contract registry (`my_contracts.py`) assembles all contracts and exposes a `contracts()` method called at startup 
to register with the `OpenAEV` platform.

---

## Configuration

### Pydantic BaseSettings

All configuration uses **Pydantic BaseSettings** (`pydantic-settings`). This replaces manual YAML parsing used in older 
injectors.

```python
# models/configs/my_service_configs.py

from pydantic import Field, SecretStr, PositiveInt
from pydantic_settings import BaseSettings

class _ConfigLoaderMyService(BaseSettings):
    """Service-specific configuration."""

    base_url: str = Field(
        default="https://api.myservice.com/v1",
        description="Base URL for the external API.",
    )
    api_key: SecretStr = Field(
        description="API key for the external service.",
    )
    api_retry: PositiveInt = Field(
        default=5,
        description="Maximum number of retry attempts.",
    )
```

```python
# models/configs/config_loader.py

from pydantic_settings import BaseSettings, SettingsConfigDict

class ConfigLoader(BaseSettings):
    model_config = SettingsConfigDict(
        env_nested_delimiter="__",
        yaml_file="config.yml",
        env_ignore_empty=True,
    )

    openaev: _ConfigLoaderOpenAEV
    injector: _ConfigLoaderInjector
    my_service: _ConfigLoaderMyService
```

Fields are populated from environment variables (priority) or `config.yml`. Secrets use `SecretStr` — access the value only when needed via `.get_secret_value()`.

### Environment Variables

Environment variable names are derived from the `BaseSettings` field path with `_` as the nesting delimiter:

| Environment variable  | Field path            | 
|-----------------------|-----------------------|
| `OPENAEV_URL`         | `openaev.url`         | 
| `OPENAEV_TOKEN`       | `openaev.token`       | 
| `OPENAEV_TENANT_ID`   | `openaev.tenant_id`   | 
| `INJECTOR_ID`         | `injector.id`         | 
| `INJECTOR_NAME`       | `injector.name`       | 
| `INJECTOR_LOG_LEVEL`  | `injector.log_level`  | 
| `MY_INJECTOR_API_KEY` | `my_injector.api_key` | 

All variables must be documented in `config.yml.sample`, `.env.sample` `docker-compose.yml`, and `README.md`.

### Secrets Management

- API keys and tokens are declared as `SecretStr` fields — Pydantic prevents accidental `.repr()` or logging exposure.
- Call `.get_secret_value()` only at the call site where the value is needed (e.g. building an HTTP request URL).
- Secrets must never appear in log output, error messages, or structured output returned to the platform.

---

## Platform Communication via pyoaev

The `pyoaev` library abstracts all communication with the `OpenAEV` platform:

- **Registration:** on startup, the injector registers itself and its contracts via the OpenAEV API.
- **Message consumption:** `helper.listen(message_callback=self.process_message)` subscribes to RabbitMQ and invokes the callback per inject execution message.
- **Reception acknowledgement:** call `helper.api.inject.execution_reception()` immediately on receiving a message to inform the platform.
- **Result reporting:** call `helper.api.inject.execution_callback()` on completion (success or error).

The standard `process_message` skeleton:

```python
def process_message(self, data: dict) -> None:
    inject_id = data["injection"]["inject_id"]
    start = time.time()

    # Acknowledge reception
    self.helper.api.inject.execution_reception(
        inject_id=inject_id, data={"tracking_total_count": 1}
    )

    try:
        output_structured, output_message = self._execute(data)
        self.helper.api.inject.execution_callback(
            inject_id=inject_id,
            data={
                "execution_message": output_message,
                "execution_output_structured": json.dumps(output_structured),
                "execution_status": "SUCCESS",
                "execution_duration": int(time.time() - start),
                "execution_action": "complete",
            },
        )
    except Exception as err:
        self.helper.injector_logger.error("Execution error", {"error": str(err)})
        self.helper.api.inject.execution_callback(
            inject_id=inject_id,
            data={
                "execution_message": str(err),
                "execution_status": "ERROR",
                "execution_duration": int(time.time() - start),
                "execution_action": "complete",
            },
        )

def start(self):
    self.helper.listen(message_callback=self.process_message)
```

---

## Logging

Use `self.helper.injector_logger`. Do not use `print()` or configure a separate handler.

```python
# Correct
self.helper.injector_logger.info("Search completed", {"count": len(results)})
self.helper.injector_logger.error("API call failed", {"status": 429})
self.helper.injector_logger.debug("Request params", {"url": safe_url, "params": safe_params})

# Incorrect
print("done")
import logging; logging.info("done")
```

Rules:
- Log inject start and end at `info` with the inject ID.
- Log external API calls at `debug` — URL and method only, never the API key.
- Log errors at `error` with enough context to diagnose without secrets.
- Never log `SecretStr` values or personally identifiable information.

---

## Error Handling

Errors fall into two categories:

**Configuration errors** (startup): missing required fields, invalid URL, unreachable service. Use Pydantic `ValidationError` — let it propagate to `main()` which catches it and calls `sys.exit(2)`.

**Execution errors** (per inject): API failures, parsing errors, no targets found. Catch inside `process_message` and report as `execution_status: "ERROR"` via `execution_callback`. Never let an unhandled exception propagate out of `process_message`.

Use custom exception classes defined in `models/exceptions.py` for domain-specific errors:

```python
class MissingRequiredFieldError(ValueError): pass
class NoTargetsRecovered(ValueError): pass
class InvalidContractError(ValueError): pass
```

---

## Result Reporting

Every inject execution must produce a result, whether it succeeded or failed. The result includes:

- `execution_status`: `"SUCCESS"` or `"ERROR"`
- `execution_message`: human-readable output rendered in the OpenAEV UI (use `output_trace_config` for rich formatting)
- `execution_output_structured`: JSON-serialised Pydantic model (assets, findings) — `json.dumps(output_structured)`
- `execution_duration`: wall-clock seconds as integer
- `execution_action`: always `"complete"` for terminal results

Structured output (e.g. auto-created assets) uses Pydantic models from `models/output_structured.py` and is serialised via `.model_dump()` before JSON encoding.

---

## Local Development Setup

```bash
cd my_injector

# Install all dependencies including dev extras
poetry install -E dev

# Configure (environment variables preferred in Docker; config.yml for local dev)
cp config.yml.sample config.yml
# Set OPENAEV__URL, OPENAEV__TOKEN, INJECTOR__ID, MY_SERVICE__API_KEY

# Run the injector
poetry run python -m my_injector
```

Once running, the injector appears in OpenAEV under **Integrations > Injectors**. Create a test inject via the UI to verify the full execution cycle.

**Debugging tips:**
- Set `INJECTOR__LOG_LEVEL=debug` to trace the full request/response cycle.
- Use `docker compose logs -f injector-my-injector` when running containerised.

---

## Testing

**All tests use pytest.** Tests must pass without network access, mock all external calls via `unittest.mock.patch` 
and `pytest`.

Shared fixtures live in `tests/conftest.py`. The standard fixture pattern uses `Mock()` for config and helper:

```python
# tests/conftest.py
from unittest.mock import Mock
from pytest import fixture
from my_injector.services.client_api import MyServiceClientAPI

@fixture
def my_service_client() -> MyServiceClientAPI:
    mock_helper = Mock()
    mock_config = Mock()
    mock_config.my_service.base_url = "https://api.myservice.com/v1"
    mock_config.my_service.api_key.get_secret_value.return_value = "test-api-key"
    mock_config.my_service.api_retry = 1
    mock_config.my_service.api_backoff.total_seconds.return_value = 1
    mock_config.shodan.api_leaky_bucket_rate = 10
    mock_config.shodan.api_leaky_bucket_capacity = 10

    return MyServiceClientAPI(config=mock_config, helper=mock_helper)

```

All injectors **MUST** include a complete test suite covering their business behaviors. These tests are not only meant to 
ensure technical correctness but also to serve as executable documentation of the injector’s capabilities.

All injector **MUST** define its main use cases using Gherkin scenarios. These `.feature`, `.constraint` files describe 
expected behaviors in a human-readable format and must remain synchronized with their corresponding pytest implementations.

```bash
poetry run pytest tests/ -v
```

---

## Docker Packaging

```dockerfile
FROM python:3.13-alpine AS builder

RUN apk update && apk upgrade && apk add git

WORKDIR /opt/injector_common
COPY --from=injector_common ./ ./

WORKDIR /
RUN git clone https://github.com/OpenAEV-Platform/client-python

# poetry version available on Ubuntu 24.04
RUN pip3 install poetry==2.3.2 \
    && poetry config installer.re-resolve false \
    && poetry config virtualenvs.create false

ARG installdir=/opt/injector
ADD . ${installdir}
WORKDIR ${installdir}
RUN poetry install

FROM python:3.13-alpine AS runner

WORKDIR /opt/injector_common
COPY --from=injector_common ./ ./

ARG installdir=/opt/injector
WORKDIR ${installdir}
COPY --from=builder ${installdir} ${installdir}
COPY --from=builder /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages

# Declare the build argument
ARG PYOAEV_GIT_BRANCH_OVERRIDE

RUN if [[ ${PYOAEV_GIT_BRANCH_OVERRIDE} ]] ; then \
        echo "Forcing specific version of client-python" && \
        apk add --no-cache git && \
        pip install pip3-autoremove && \
        pip-autoremove pyoaev -y && \
        pip install git+https://github.com/OpenAEV-Platform/client-python@${PYOAEV_GIT_BRANCH_OVERRIDE} ; \
    fi

CMD ["python3", "-m", "my_injector"]
```

Build and verify locally:

```bash
docker compose build
docker compose up -d
docker compose logs -f
```

For injectors that depend on `injector_common`, use the `--build-context` flag:

```bash
docker build --build-context injector_common=../injector_common -t openaev/injector-my-injector:test .
```