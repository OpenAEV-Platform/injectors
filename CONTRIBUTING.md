---  
version: 1.0  
category: Documentation  
audience: Partners, Customers, Community Contributors, Internal Team Members  
maintainers: XTM Integrations Team  
last updated: May 2026  
status: Draft  
---

# OpenAEV Injector Development Guidelines

## Table of Contents

- [OpenAEV Injector Development Guidelines](#openaev-injector-development-guidelines)
  - [Introduction](#introduction)
    - [What is an Injector?](#what-is-an-injector)
      - [Inject Types Covered](#inject-types-covered)
      - [What is a contract?](#what-is-a-contract)
  - [Prerequisites](#prerequisites)
    - [Technical Requirements](#technical-requirements)
    - [Knowledge Requirements](#knowledge-requirements)
    - [Development Environment](#development-environment)
  - [Getting Started](#getting-started)
    - [Quick Start](#quick-start)
    - [Initial Setup](#initial-setup)
      - [Configuration (Environment Variables)](#configuration-environment-variables)
      - [Development Requirements](#development-requirements)
      - [Runtime Requirements](#runtime-requirements)
    - [Creating a New Injector](#creating-a-new-injector)
      - [Choosing the right inject type](#choosing-the-right-inject-type)
    - [Understanding the Template Structure](#understanding-the-template-structure)
  - [Documentation Structure](#documentation-structure)
    - [Core Documentation](#core-documentation)
    - [Inject Types Reference](#inject-types-reference)
  - [Quick Overview](#quick-overview)
    - [Common Implementation Guidelines](#common-implementation-guidelines)
    - [Inject Type Specific Guidelines](#inject-type-specific-guidelines)
    - [Code quality standards](#code-quality-standards)
    - [Linting Requirements](#linting-requirements)
    - [Testing Requirements](#testing-requirements)
      - [What is Gherkin?](#what-is-gherkin)
      - [Why use Gherkin?](#why-use-gherkin)
    - [Docker Standards](#docker-standards)
    - [Documentation Standards](#documentation-standards)
  - [Getting Help](#getting-help)
    - [Resources](#resources)
    - [Community Support](#community-support)
    - [Contributing](#contributing)
  - [Quick Reference](#quick-reference)

---
## Introduction
Welcome to the OpenAEV Injector Development Guidelines. This documentation provides everything you need to build, test, 
and contribute an injector to the OpenAEV ecosystem, whether you are a Filigran partner, a community contributor, or an 
internal team member.

> [!WARNING]
>
> This document is subject to change. We are currently working on a standardized template for injectors.

### What is an Injector?
An **injector** is an autonomous, containerised Python process that extends the **OpenAEV** platform by handling a 
specific type of inject. When a simulation or atomic test triggers an inject, OpenAEV publishes a message to RabbitMQ,
the relevant injector consumes that message, executes the corresponding action against a third-party system, subprocess 
or API, and reports the result back to the platform.

Injectors are stateless by design: all configuration is supplied at startup via environment variables or a config.yml 
file, and each execution is independent.

> [!NOTE]
> 
> Built-in injectors: Some injectors such as email, SMS, media pressure, etc. are directly embedded into the application OpenAEV. To configure them, just add the proper configuration parameters in your platform configuration.

#### Inject Types Covered

Here is the complete list of available injector types:
- **Manual action reminders**
- **Direct contact**
- **Media pressure**
- **Challenges**
- **HTTP requests**
- **Technical Injects via Agent**
- **Agentless Injectors**

The following inject types are officially documented in the [OpenAEV site](https://docs.openaev.io/latest/usage/inject-types/)

Deeply documented type in this repository:
- [Common implementation](./docs/inject_types/01-common-implementation.md)

#### What is a contract?
A contract is the formal definition of the parameters, validation rules, and execution schema that an injector exposes 
to the OpenAEV platform. It is the interface between what the platform renders to the user and what the injector 
receives at execution time.

Contracts can be triggered through two execution contexts:
- Atomic testings (standalone inject executions outside of a scenario)
- Scenarios (orchestrated sequences of injects within a simulation)

Each contract defines:
- The **available fields** presented to the user in the inject configuration form
- The **parameter types** for each field (e.g. `ContractText`, `ContractTuple`, `ContractCheckbox`, `ContractSelect`).
- Which fields are **required** before an inject can be saved or executed
- **Default values** pre-filled in the form when no value is provided
- **Visibility and mandatory conditions**, fields can appear or become required dynamically based on the value of another 
field (e.g. a `hostname` field visible only when the target selector is `manual`)

A contract serves two complementary purposes:

- **Platform-side**: 
  - OpenAEV reads the contract to dynamically render the inject configuration interface. Users fill in the contract 
  fields, the platform validates input against the contract rules before dispatching execution.
- **Injector-side**: 
  - The injector receives the user-supplied values as a typed Pydantic model matching the contract schema, validated 
  before the execution callback is invoked.

For Python injectors, contracts are defined using the `pyoaev` library maintained by the XTM Integrations Team.

Contract classes are defined at the level of each injector and are stored in the `<myinjector>/contracts/` directory. 
Each contract has its own subdirectory to facilitate navigation and code organization.

An injector may expose **one or more contracts**, depending on the inject types and execution paths it supports.

---
## Prerequisites

### Technical Requirements

| Requirement                                                                       | Recommended Version | Purpose                                                                                         |
|-----------------------------------------------------------------------------------|---------------------|-------------------------------------------------------------------------------------------------|
| Python                                                                            | `>=3.11,<4.0`       | Primary runtime environment for all injectors                                                   |
| Pyoaev (`client-python`)                                                          | `2.260521.0`        | OpenAEV Python SDK used for injector contracts, runtime integration, and platform communication |
| [Docker](https://docs.docker.com/engine/install/)                                 | `>=24`              | Containerized injector execution and deployment                                                 |
| [Docker Compose](https://docs.docker.com/compose/install/)                        | `v2+`               | Local development stack orchestration and multi-service management                              |
| [Pydantic](https://docs.pydantic.dev/latest/)                                     | `~=2.11.7`          | Data validation, schema enforcement, and typed runtime models                                   |
| [Pydantic Settings](https://docs.pydantic.dev/latest/concepts/pydantic_settings/) | `~=2.11.0`          | Environment-based configuration and secrets management                                          |

### Knowledge Requirements

To contribute an injector, you should be comfortable with:
- Proficiency in **Python programming (3.11+)**
- **Pydantic** v2 models and **Pydantic Settings**
- **Git branching** and the **Pull Request** workflow
- **Docker** and **Docker Compose** fundamentals

For HTTP Request injectors, familiarity with the target API (authentication schemes, rate limiting, pagination) is 
required before starting.

### Development Environment
A running OpenAEV instance is required to register and test an injector locally. 
The quickest path is the OpenAEV Docker stack. 

You can develop an injector using either:

1. **Docker Environment** (Recommended for production-like testing)
  - Requires Docker Compose knowledge
  - Best for integration testing
  - See [Docker Setup Guide](./docs/inject_types/01-common-implementation.md#docker-packaging)

2. **Local Environment** (Recommended for development)
  - Faster iteration cycle
  - Easier debugging
  - See [Local Setup Guide](./docs/inject_types/01-common-implementation.md#configuration)

---
## Getting Started

### Quick Start

1. Identify the appropriate injector type for your use case
2. Prepare your local development environment
3. Bootstrap the injector from the provided template (WIP - In the meantime, see `Injector Structure` in [Common implementation](./docs/inject_types/01-common-implementation.md))
4. Review the documentation and specifications for the targeted inject type
5. Design and implement the injector contracts
6. Implement the runtime and business logic
7. Validate the injector through local testing and CI workflows
8. Submit a Pull Request for review

### Initial Setup
```bash
# 1. Fork then clone the repository
git clone https://github.com/<your-username>/injectors.git
cd injectors

# 2. Add the upstream repository
git remote add upstream https://github.com/OpenAEV-Platform/injectors.git

# 3. Create a dedicated feature branch
git switch -c feature/my-injector-name

# 4. Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate

# 5. Install project dependencies using your preferred Python package manager
# Examples:
# uv sync
# pip install -e .
# poetry install

# 6. Install and configure pre-commit hooks
pre-commit install
```

#### Configuration (Environment Variables)
Injectors can be configured using one of the following approaches:

```bash
# YAML-based configuration
cp config.yml.sample config.yml

# environment-based configuration
cp .env.sample .env

# Docker-based configuration
docker compose up --build
```

#### Development Requirements

The repository follows standard Python packaging conventions based on `pyproject.toml` and `PEP-compliant Python packaging`.
Contributors are free to use their preferred Python package manager or build backend.

Current tooling: 
- [Poetry](https://python-poetry.org/docs/)

Recommended tooling:
- [UV](https://docs.astral.sh/uv/getting-started/)

#### Runtime Requirements

It is important to note that pyoaev is a required dependency for the correct functioning of all injectors.

You must ensure it is available in your development environment by either:

1. Local setup (sibling repository):
```
├── client-python/     # mandatory directory name (pyoaev dependency)
│   └── pyoaev/
└── injectors/
    ├── my-injector-name/
    └── ...
```
- Clone the repository client-python: `git clone https://github.com/<your-username>/client-python`

2. Docker-based environment
- Use the official [OpenAEV platform image](https://hub.docker.com/r/openaev/platform). This image already includes the 
required runtime dependencies, including pyoaev.

### Creating a new injector
Then build the structure following the key files to create are listed in `Understanding the Template Structure`.

#### Choosing the right inject type
Before writing any code, identify which inject type your injector implements (see [Inject Types Covered](#inject-types-covered)). 
This determines:

- Which `pyoaev` contract classes to use.
- Whether an `executor / agent` is involved.
- Whether an external API call is involved.
- Which documentation file under `docs/inject_types/` applies.

### Understanding the Template Structure

All injectors follow this standardized structure (see section `Injector Structure`) in [Common Implementation Guidelines](./docs/inject_types/01-common-implementation.md)

---
## Documentation Structure

### Core Documentation

| File                                            | Description                                                       | 
|-------------------------------------------------|-------------------------------------------------------------------|
| `CONTRIBUTING.md`                               | Entry point for all contributors                                  |
| `CODE_OF_CONDUCT.md`                            | Community behavioural expectations                                |
| `docs/inject_types/01-common-implementation.md` | Implementation patterns shared by all inject types                |

### Inject-Types Reference

| Type                  | Description                                                                       | Injects                                                | Agent required   |
|-----------------------|-----------------------------------------------------------------------------------|--------------------------------------------------------|------------------|
| `Manual actions`      | Operational reminders for the exercise team to perform external actions           | `Manual`                                               | No               |
| `Direct contact`      | Email/SMS communications simulating social engineering or threat messages         | `Send SMS`, `Send individual email`, `Send bulk email` | No               |
| `Media pressure`      | Publishing simulated media content to create reputational or operational pressure | `Publish channel pressure`                             | No               |
| `Challenges`          | Security or operational challenges delivered to participants                      | `Publish challenges`                                   | No               |
| `HTTP requests`       | External HTTP calls to trigger third-party systems (e.g. EDR, APIs)               | `HTTP GET`, `HTTP POST`, `HTTP PUT`                    | No               |
| `Agent-based injects` | Execution of actions via OpenAEV Agent on target endpoints                        | Depends on configured executor/arsenal                 | Yes              |
| `Agentless injects`   | Remote scanning or probing without installed agent (IP/hostname-based)            | Nmap, Nuclei                                           | No               |

See full reference: [Docs OpenAEV Inject Types](https://docs.openaev.io/latest/usage/inject-types/)

---
## Quick Overview

### Common Implementation Guidelines

All injectors, regardless of type, must:

- Use `pyoaev` for platform communication (registration, message consumption, result reporting).
- Define `contracts` via pyoaev contract classes, one contract class per subdirectory.
- Use `Pydantic BaseSettings` for configuration, never parse `config.yml` manually.
- Use `Pydantic BaseModel` for all data structures (inject content, targets, outputs).
- Use the `logger` provided by the pyoaev helper (`helper.injector_logger.info`), never `print()`.
- Handle errors gracefully per execution and report failures back to the platform.

See full reference: [Common Implementation Guidelines](./docs/inject_types/01-common-implementation.md)

### Inject Type Specific Guidelines

For HTTP Request injectors:

- Authentication credentials are stored as pydantic.SecretStr and never logged.
- Rate limiting to control request throughput.
- Retry handling with exponential backoff.
- Request construction is isolated in a dedicated `services/client_api.py` layer.
- Input is normalised and validated through `Pydantic` discriminated union models before execution.
- Remove API keys from URLs before any logging.

> [!NOTE]
> 
> All guidelines are currently being developed.

### Code quality standards
- Code style follows Black and Ruff conventions (PEP 8 compatible).
- Type hints are mandatory throughout the codebase.
  - mypy --strict must pass (with documented exceptions if needed for external API models).
- Docstrings use Google style for all public functions and classes.
- Line length: 88 characters (enforced by Black; Ruff line-length rule disabled to avoid duplication).
- No magic values:
  - Use named constants
  - Prefer `Pydantic models` with defaults

### Linting Requirements

The following tools are configured in `.pre-commit-config.yaml` and `pyproject.toml` and are mandatory:

| Tool    | Role                 | Notes                                |
|---------|----------------------|--------------------------------------|
| `isort` | Import ordering      | Profile: black                       |
| `black` | Code formatting      | 88 char lines                        |
| `ruff`  | Fast linting         | Replaces flake8 for new injectors    |
| `mypy`  | Static type checking | strict=true, pydantic plugin enabled |

Legacy injectors (nmap, nuclei, http-query, aws) still use flake8: 
- New injectors (e.g. Shodan) must use ruff + mypy.

Run all checks locally before opening a PR:
```bash
isort --profile black <path_to_connector>
black <path_to_connector>
ruff check <path_to_connector>
mypy <path_to_connector>
```
Or via pre-commit:
```bash
pre-commit run --all-files
```

### Testing Requirements
Tests must be deterministic and must not require real network access.

- All new code must be accompanied by tests.
- **Unit tests** (with `pytest`) for all core functionality
- Test configuration validation
- Test error handling paths
- Using `Gherkin` to easily identify use cases

#### What is Gherkin?
https://cucumber.io/docs/gherkin/

Gherkin is a plain-language syntax for describing the behavior of a system in human-understandable scenarios, structured
around the `Given`, `When`, and `Then` steps. 

Example:
```gherkin
Scenario: API key must never appear in logs
  Given an injector is executed
  When results are generated
  Then the logs must not contain any API key
```

By project convention, `.feature` files are located in the same directory as their test module.

Example:
```
tests/shodan_contracts/domain_discovery/
└── domain_discovery.feature   <- Gherkin specification
```

#### Why use Gherkin?

- **Shared language**: scenarios are readable by **developers**, **QA**, and **product** stakeholders without reading code.
- **Living documentation**: `.feature` files describe exactly what the contract does, staying in sync with the implementation.
- **Regression safety**: catches regressions in contract execution logic independently of internal implementation changes.
- **Contract constraints**: expected behaviors, validation rules, and security requirements are captured as executable specifications.

### Docker Standards
Every injector must include a functional `Dockerfile` and `docker-compose.yml`. 

Key requirements:
- Use a `python:3.x-alpine` base image with a Python version >=3.11 and <3.14
- Minimize layer count and image size
- Include health checks where applicable
- Follow security best practices (non-root user, minimal packages)
- Document all environment variables

```yaml
services:
  injector-my-injector:
    image: openaev/injector-my-injector:latest
    environment:
      - OPENAEV_URL=${OPENAEV_URL}
      - OPENAEV_TOKEN=${OPENAEV_TOKEN}
      - OPENAEV_TENANT_ID=${OPENAEV_TENANT_ID}
      - INJECTOR_ID=${INJECTOR_ID}
      - INJECTOR_NAME=${INJECTOR_NAME}
      - INJECTOR_LOG_LEVEL=${INJECTOR_LOG_LEVEL}
    restart: always
```

### Documentation Standards

Every injector must ship with:

- Complete `README.md` with:
  - Injector description and use cases
  - Setup and deployment instructions
  - Prerequisites and dependencies
  - Troubleshooting guide

- `config.yml.sample` (and `.env.sample`) with all supported keys and `ChangeMe` placeholders — no real credentials.
- `manifest-metadata.json` for Integration Manager support:

Example (`manifest-metadata.json`):
```json
{
  "title": "My Injector",
  "slug": "openaev_my_injector",
  "description": "Description",
  "short_description": "Short description",
  "use_cases": [],
  "verified": false,
  "last_verified_date": "",
  "playbook_supported": false,
  "max_confidence_level": 80,
  "support_version": "",
  "subscription_link": "",
  "source_code": "",
  "manager_supported": true,
  "container_version": "rolling",
  "container_image": "openaev/injector-my-injector",
  "container_type": "INJECTOR"
}
```

---
## Getting Help

### Resources
- **Filigran Homepage**: https://filigran.io/
- **GitHub Repository**: https://github.com/OpenAEV-Platform/injectors/
- **GitHub Documentation**: https://github.com/OpenAEV-Platform/injectors/blob/main/README.md
- **GitHub Issues**: https://github.com/OpenAEV-Platform/injectors/issues
- **OpenAEV Ecosystem**: https://filigran.notion.site/OpenAEV-Ecosystem-30d8eb73d7d04611843e758ddef8941b
- **OpenAEV client for Python**: https://pypi.org/project/pyoaev/
- **Documentation inject types**: https://docs.openaev.io/latest/usage/inject-types/
- **Documentation injector development**: https://docs.openaev.io/2.4.X/development/injectors/

### Community Support

For questions and community help:

- **Slack Community**: [https://community.filigran.io](https://community.filigran.io)
- **GitHub Issues**: [https://github.com/OpenAEV-Platform/injectors/issues](https://github.com/OpenAEV-Platform/injectors/issues)

### Contributing

We welcome contributions including:
- New injectors
- Bug fixes
- Documentation improvements
- Test coverage improvements

Before opening a Pull Request:
- Search existing issues and pull requests
- Open an issue for:
  - New injector proposals
  - Architectural changes
  - Large refactors or shared framework modifications
  - Bugs / Fixes

This helps avoid duplicated work and ensures alignment with maintainers.

**Branch naming convention**: All branches must follow this naming convention:

| Type          | Pattern                                |
|---------------|----------------------------------------|
| New feature   | `feat/<issue>-<injector>-<name>`       | 
| New Bug fix   | `fix/<issue>-<injector>-<description>` | 
| Documentation | `docs/<issue>-<description>`           | 
| CI            | `ci/<issue>-<description>`             |

**Commit and PR title format**: This repository enforces a strict commit convention validated in CI.
Format:
```
type(scope?)!?: description (#123)
```
- **type**: one of `feat`, `fix`, `chore`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `revert`
- **scope**: optional — use the injector name or affected area
- **description**: must start with a lowercase letter
- **`(#123)`**: required — the linked issue number at the end
- Examples: `feat(http-request): add retry mechanism (#42)`, `fix: resolve config loading issue (#99)`

For more information, see [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)

All PRs must pass the following checks before review:

- [ ] isort + black + ruff + mypy pass locally
- [ ] Test coverage is sufficient and pytest runs successfully
- [ ] Gherkin .feature added or updated
- [ ] README.md updated if needed
- [ ] config.yml.sample updated if configuration changed
- [ ] manifest-metadata.json present and valid
- [ ] No secrets, tokens, or real credentials committed
- [ ] Dockerfile builds successfully
- [ ] docker-compose runs locally
- [ ] All environment variables documented
- [ ] Responsive to review feedback from maintainers

> [!WARNING]
> 
> - All Pull Requests must be accompanied by a linked GitHub issue describing the motivation and impact of the change.
> - All commits must be signed (GPG or SSH signing enabled).

---
## Quick Reference

| Need to...               | See Document                            | Section         |
|--------------------------|-----------------------------------------|-----------------|
| Read the code of conduct | [CODE_OF_CONDUCT](./CODE_OF_CONDUCT.md) | CODE OF CONDUCT |

---

**Ready to start?** Proceed to [Common Implementation Guidelines](./docs/01-common-implementation.md) to begin developing
your injector.
---
