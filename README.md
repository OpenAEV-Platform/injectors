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
```shell
poetry install --with dev,test
```

### Creating a new injector

Assuming a new injector by the name of `new_injector`, create a skeleton directory with:
```shell
poetry new new_injector
```

### Add pyoaev as a requirement

Inside the new directory `new_injector`, add `pyoaev` to the current requirements:
```shell
poetry add pyoaev
```

### Add injector\_common as a requirement

`injector_common` is currently provided as part of this project and should be added as a local path requirement. This can be achieved by adding the following line to the dependencies included in the `pyproject.toml`:
```
injector_common = { path = "../injector_common", develop = true }
```

### Simultaneous development on pyoaev and an injector

Two options: local path requirement and install post-poetry.

Regarding, the local path requirement, the approach is similar to `injector_common`. If both the `client-python` and the `injectors` git projects are in a same folder, the dependency for `pyoaev` can thus be the following:
```
pyoaev = { path = "../../client-python", develop = true }
```

Regarding the install post-poetry, after the `poetry install --with dev,test`, it is still possible to `pip install` a different version of pyoaev in your (virtual) environment, whether a local one or from github (e.g. to install the `head` of `main`).

Note that for container-based development and testing, the `PYOAEV_GIT_BRANCH_OVERRIDE` build argument is available to override the `pyproject.toml`-pinned version with one from a git branch.

## Contributing

If you want to help use improve or develop new injector, please check out the **[development documentation for new injectors](https://docs.openaev.io/latest/development/injectors)**. If you want to make your injectors available to the community, **please create a Pull Request on this repository**, then we will integrate it to the CI and in the [OpenAEV ecosystem](https://filigran.notion.site/OpenAEV-Ecosystem-30d8eb73d7d04611843e758ddef8941b).

## License

**Unless specified otherwise**, injectors are released under the [Apache 2.0](https://github.com/OpenAEV-Platform/injectors/blob/main/LICENSE). If an injector is released by its author under a different license, the subfolder corresponding to it will contain a *LICENSE* file.

## About

OpenAEV is a product designed and developed by the company [Filigran](https://filigran.io).

<a href="https://filigran.io" alt="Filigran"><img src="https://github.com/OpenAEV-Platform/openaev/raw/master/.github/img/logo_filigran.png" width="300" /></a>
