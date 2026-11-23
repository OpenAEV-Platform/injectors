# OpenAEV Injectors - Copilot Instructions

## Repository Overview

**Python monorepo** with one directory per injector (`nuclei/`, `nmap/`, `http-query/`, `aws/`, `shodan/`, `netexec/`…), plus `injector_common/` (shared code for nmap/nuclei) and `libs/injectors-sdk/` (the injector runtime SDK). Python 3.12+ (`pyoaev` needs it; Docker images: Python 3.13), Docker, CircleCI, pyoaev client.

## Critical Build & Test Commands

### Code Formatting & Linting (ALWAYS RUN BEFORE COMMITTING)

**IMPORTANT:** CircleCI will fail PRs that don't pass formatting checks. Always run these in order:

```bash
# 1. Install tools (only needed once)
pip install black isort flake8 --user

# 2. Run isort (import sorting) - MUST pass
isort --profile black --check .
# To fix: isort --profile black .

# 3. Run black (code formatting) - MUST pass  
black --check .
# To fix: black .

# 4. Run flake8 (linting) - MUST pass
flake8 --ignore=E,W .
```

**Note:** The `--ignore=E,W` flag is required for flake8. This is configured in `.flake8` and `.pre-commit-config.yaml`.

### Testing Individual Injectors

Each injector has its own test suite. Tests MUST pass before committing.

```bash
# Nuclei injector
cd nuclei
pip install -r requirements.txt
python -m unittest

# Nmap injector  
cd nmap
pip install -r requirements.txt
python -m unittest

# HTTP Query injector
cd http-query
pip install -r src/requirements.txt
python -m unittest
```

**AWS injector has no tests currently.**

### Docker Builds

Docker builds are part of CI but can be tested locally:

```bash
# Nuclei (requires build context)
cd nuclei
docker build --build-context injector_common=../injector_common -t openaev/injector-nuclei:test .

# Nmap (requires build context)
cd nmap  
docker build --build-context injector_common=../injector_common -t openaev/injector-nmap:test .

# HTTP Query (standalone)
cd http-query
docker build -t openaev/injector-http-query:test .

# AWS
cd aws
docker build -t openaev/injector-aws:test .
```

**Build Context Note:** The `--build-context injector_common=../injector_common` flag is required for nuclei and nmap. This is a Docker buildx feature that makes the shared code available during build.

## pyoaev and the SDKs

**Read this before touching imports or dependencies.** The shared runtime of `pyoaev` is
moving into SDKs: `libs/injectors-sdk/` in this repository and `xtm-oaev-sdk` in `client-python`.
`pyoaev` keeps the OpenAEV API client and serves the former names through deprecation
shims. The released `pyoaev` versions the injectors pin today do **not** ship the SDKs.

- **Keep the existing `pyoaev` imports** as long as the injector's pinned `pyoaev` does not
  depend on the SDKs. **NEVER** import `injectors_sdk` or `xtm_oaev_sdk` in such a injector: the
  production install takes `pyoaev` from PyPI, where the SDKs do not exist, and the
  injector fails at runtime.
- **Check:** in the injector's environment, `pip show pyoaev` lists `injectors-sdk` under `Requires`.
- **NEVER** change a `pyoaev` pin or extra marker, or add an SDK dependency, without team
  approval.
- With a local `client-python`, `pyoaev` now also requires `xtm-oaev-sdk`,
  `collectors-sdk` and `injectors-sdk`. If they cannot be resolved, report it instead of
  editing pins.
- **Migrating** (only when requested, and once the check passes): replace each legacy
  import with the one its `DeprecationWarning` names, from the package root
  (`from injectors_sdk import OpenAEVInjectorHelper`, never `public`, `seam` or `_core`), and pass the client yourself:
  `OpenAEVInjectorHelper(config, icon, api_client=OpenAEV(...))`. See the [migration guide](https://github.com/OpenAEV-Platform/client-python/blob/main/libs/xtm-oaev-sdk/docs/migration_guide.md).
- **Working in `libs/injectors-sdk/`:** follow `libs/injectors-sdk/CONTRIBUTING.md`. Run its linters from
  the repository root and its tests from `libs/injectors-sdk/`; CI does not run them.

## Repository Structure (Key Files Only)

**Injectors:** Each in own directory with `Dockerfile`, `requirements.txt`, `test/`, main entry `openaev_<name>.py`
- `nuclei/nuclei/` - Source (helpers/, nuclei_contracts/), pyproject.toml
- `nmap/src/` - Source (contracts/, helpers/)
- `http-query/src/` - Source (contracts_http.py), requirements in src/
- `aws/src/` - Source (contracts_aws.py, helpers/)
- `libs/injectors-sdk/` - The injector runtime SDK (see "pyoaev and the SDKs")
- `injector_common/injector_common/` - Shared: targets.py, pagination.py, constants.py

**Config/CI:**
- `.circleci/config.yml` - Main CI pipeline (formatting, linting, tests, builds, deploys)
- `.github/workflows/` - release.yml, validate-pr-title.yml
- `.flake8` - Linting config: ignore E,W; max-line-length 120
- `.pre-commit-config.yaml` - black, flake8, isort hooks
- `scripts/release.py` - Version update automation

## CircleCI Pipeline (All Checks Must Pass)

**Every PR/Commit runs:** ensure_formatting → linter → test-nuclei → test-nmap → test-http-query

1. **ensure_formatting** - `isort --profile black --check .` and `black --check .` (Python 3.13)
2. **linter** - `flake8 --ignore=E,W ~/repo` (alpine/flake8 image)
3. **test-{injector}** - `pip install -r requirements.txt`, overwrite pyoaev from main/release branch, `python -m unittest` (Python 3.13)

**Build jobs** (main/release/tags only):
- **build_rolling_1** - Builds all injectors with `rolling` tag, runs on main
- **build_prerelease_1** - Builds with `prerelease` tag, runs on release/current  
- **build_1** - Versioned release builds on tags (x.x.x format)

Docker builds use `--build-context injector_common=../injector_common` for nmap/nuclei. After builds, deploys to testing/prerelease k8s environments.

## Common Issues & Solutions

**"black/isort check failed"** → Run `isort --profile black .` then `black .` and commit

**"flake8 errors"** → Fix imports/syntax errors (E,W categories already ignored via --ignore flag)

**"ModuleNotFoundError: injector_common"** (nmap/nuclei) → `pip install -r requirements.txt` includes `../injector_common`

**"Docker build: injector_common not found"** (nmap/nuclei) → Must use `--build-context injector_common=../injector_common`

**"pyoaev version mismatch"** → CI overwrites with branch version. Locally: `pip install --force-reinstall git+https://github.com/OpenAEV-Platform/client-python.git@main`

## Code Style & Conventions

**isort:** Profile `black` (pyproject.toml: `known_local_folder` per injector)
**black:** 88 char lines, must pass `black --check .`
**flake8:** Max line 120, ignores E,W. Config: `.flake8`
**Testing:** `python -m unittest` from injector root. Tests in `test/` dirs.
**Versioning:** all injectors pin the same exact `pyoaev` version. Update in requirements.txt, docker-compose.yml, __version__.

## GitHub Workflows

**PR Title:** see "Commit, PR & issue conventions" below (Conventional Commits, no bracket prefix).
**Release:** scripts/release.py updates versions via grep/sed, creates tags, generates notes with gren.

## Key Dependencies

**All:** pyoaev (exact pin, same version everywhere) | **nuclei:** Nuclei 3.4.3, Python 3.13-alpine | **nmap:** nmap+jc, Python 3.13-alpine | **aws:** Pacu+AWS CLI, Python 3.13-alpine | **http-query:** Python 3.13-alpine

## Pre-Commit Checklist

1. Format: `isort --profile black .` then `black .`
2. Lint: `flake8 --ignore=E,W .`
3. Test: `python -m unittest` for modified injectors
4. Docker (if deps changed): Test build with --build-context for nmap/nuclei
5. Review: No unintended changes, especially in other injectors

## Configuration Pattern

Each injector has `config.yml.sample`: openaev.url, openaev.token, injector.id, injector.name, injector.log_level

## Critical Notes

- **Shared code:** Only nmap/nuclei use `injector_common`. http-query/aws are standalone.
- **Entry points:** Named `openaev_<name>.py` in each injector
- **Module isolation:** Each injector is independent with own tests
- **pyoaev consistency:** Keep version same across all injectors unless specifically updating
- **SDK split:** NEVER import `injectors_sdk` or `xtm_oaev_sdk` in an injector before reading "pyoaev and the SDKs"
- **Trust these instructions:** Validated against actual codebase. Search only if incomplete/incorrect.


<!-- filigran-conventions:start -->
## Commit, PR & issue conventions

All commits, pull requests and issues in this repository follow the
[Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)
specification with a GitHub issue reference:

```
type(scope?)!?: description (#issue)
```

- Types: `feat`, `fix`, `chore`, `docs`, `style`, `refactor`, `perf`, `test`,
  `build`, `ci`, `revert`.
- The description starts with a lowercase letter and has no trailing period;
  preserve acronyms and proper nouns.
- The old `[backend]` / `[frontend]` bracket prefixes are discontinued — use a
  Conventional Commits scope instead.
- Pull request titles **must** end with the related issue reference, e.g.
  `(#1234)`, and every pull request must be linked to an issue.
- Sign your commits.

When generating commit messages, PR titles or issue titles, always follow this
convention. See [`.github/LABELS.md`](.github/LABELS.md) for the full title and
label taxonomy.
<!-- filigran-conventions:end -->


<!-- filigran-model-policy:start -->
## GitHub Copilot model usage

To keep token consumption under control, pick the model that matches the task:

- **Opus 4.6** — reserve for complex work: deep reasoning, large refactors,
  architecture design, tricky debugging. It is significantly more
  token-expensive, so it is not the daily driver.
- **Sonnet / Gemini / GPT** — default for everyday tasks: autocomplete, small
  fixes, quick questions, code explanations.

We have a limited token budget — being mindful of the model you pick makes a
real difference at scale. Think of Opus as a specialist you call in when you
really need it.
<!-- filigran-model-policy:end -->
