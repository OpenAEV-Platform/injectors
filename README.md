# OpenAEV injectors

[![Website](https://img.shields.io/badge/website-openaev.io-blue.svg)](https://openaev.io)
[![CircleCI](https://circleci.com/gh/OpenAEV-Platform/injectors.svg?style=shield)](https://circleci.com/gh/OpenAEV-Platform/injectors/tree/main)
[![Slack Status](https://img.shields.io/badge/slack-3K%2B%20members-4A154B)](https://community.filigran.io)

The following repository is used to store the OpenAEV injectors for the platform integration with other tools and applications. To know how to enable injectors on OpenAEV, please read the [dedicated documentation](https://docs.openaev.io/latest/deployment/ecosystem/injectors).

## Injectors list and statuses

This repository is used to host injectors that are supported by the core development team of OpenAEV. Nevertheless, the community is also developing a lot of injectors, third-parties modules directly linked to OpenAEV. You can find the list of all available injectors and plugins in the [OpenAEV ecosystem dedicated space](https://filigran.notion.site/OpenAEV-Ecosystem-30d8eb73d7d04611843e758ddef8941b).

## Development
This step installs all injectors within the repository inside a single poetry environment. If you do not wish
to work with all injectors at once, it is possible to install each injector within its own poetry environment. Refer
to each injector's individual README for instructions.

In this repository, you need to have `python >= 3.11` and `poetry >= 2.1`. Install the development environment with:
> [!IMPORTANT]
> This repository uses "mutually exclusive extra markers" to manage the source of the pyoaev dependency. Make sure to
> follow the steps to set up poetry correctly to handle this case:
> https://python-poetry.org/docs/dependency-specification/#exclusive-extras

```shell
poetry install --extras dev
```

### Creating a new injector

#### Project setup
Assuming a new injector by the name of `new_injector`, create a skeleton directory with:
```shell
poetry new new_injector
```

#### `pyoaev` dependency
We wish to retain the possibility to develop simultaneously on `pyoaev` and injectors. We rely on PEP 508 environment
markers to alternatively install a local path `pyoaev` dependency or a released version from PyPI; specifically the `extra`
marker.

Navigate to the new directory and edit `pyproject.toml`.
```shell
vim new_injector/pyproject.toml
```
(or open the file in your favourite editor).

Here's the expression for the pyoaev dependency, including the `extra` definition:
```toml
dependencies = [
    "pyoaev (==<latest pyoaev release on PyPI>); extra != 'dev'",
]
[project.optional-dependencies]
dev = [
    "pyoaev @ ../../client-python",
]
[tool.poetry.dependencies]
pyoaev = [
    { markers = "extra != 'dev'", source = "PyPI" },
    { markers = "extra == 'dev'", develop = true },
]
```

### Simultaneous development on pyoaev and an injector
The injectors repository is set to assume that in the event of a simultaneous development work on both `pyoaev`
and injectors, the `pyoaev` repository is cloned in a directory at the same level as the injectors root directory,
and is named strictly `client-python`.

Here's an example layout:
```
.
├── client-python       <= mandatory dir name
│   ├── docs
│   ├── pyoaev
│   ├── scripts
│   └── test
└── injectors          <= this repo root dir
    ├── ai-redteam
    ├── aws
    ├── censys
    ├── http-query
    ├── injector_common
    ├── netexec
    ├── nmap
    ├── nuclei
    ├── shodan
    ├── stratus
    └── teams
```


## Contributing

If you want to help use improve or develop new injector, please check out the **[development documentation for new injectors](https://docs.openaev.io/latest/development/injectors)**. If you want to make your injectors available to the community, **please create a Pull Request on this repository**, then we will integrate it to the CI and in the [OpenAEV ecosystem](https://filigran.notion.site/OpenAEV-Ecosystem-30d8eb73d7d04611843e758ddef8941b).

## License

**Unless specified otherwise**, injectors are released under the [Apache 2.0](https://github.com/OpenAEV-Platform/injectors/blob/main/LICENSE). If an injector is released by its author under a different license, the subfolder corresponding to it will contain a *LICENSE* file.

## About

OpenAEV is a product designed and developed by the company [Filigran](https://filigran.io).

<a href="https://filigran.io" alt="Filigran"><img src="https://github.com/OpenAEV-Platform/openaev/raw/master/.github/img/logo_filigran.png" width="300" /></a>
