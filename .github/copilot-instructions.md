# OpenAEV Injectors - Copilot Instructions

## Repository Overview

**Python monorepo** (~5,700 lines) with 4 injector modules: `nuclei/` (Nuclei scanner), `nmap/` (Nmap scanner), `http-query/` (HTTP testing), `aws/` (AWS/Pacu security), plus `injector_common/` (shared code for nmap/nuclei). Python 3.11-3.13, Docker, CircleCI, pyoaev client.

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
python -m unittest  # Runs 11 tests, should complete in <1 second

# Nmap injector  
cd nmap
pip install -r requirements.txt
python -m unittest  # Runs 4 tests, should complete in <1 second

# HTTP Query injector
cd http-query
pip install -r src/requirements.txt
python -m unittest  # Runs 4 tests, should complete in <1 second
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

# AWS (uses Python 3.11-slim, not Alpine)
cd aws
docker build -t openaev/injector-aws:test .
```

**Build Context Note:** The `--build-context injector_common=../injector_common` flag is required for nuclei and nmap. This is a Docker buildx feature that makes the shared code available during build.

## Repository Structure (Key Files Only)

**Injectors:** Each in own directory with `Dockerfile`, `requirements.txt`, `test/`, main entry `openaev_<name>.py`
- `nuclei/nuclei/` - Source (helpers/, nuclei_contracts/), pyproject.toml
- `nmap/src/` - Source (contracts/, helpers/)
- `http-query/src/` - Source (contracts_http.py), requirements in src/
- `aws/src/` - Source (contracts_aws.py, helpers/), Python 3.11-slim Docker
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
- **build_rolling_1** - Builds all 4 injectors with `rolling` tag, runs on main
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

**isort:** Profile `black`, configured in pyproject.toml with `known_local_folder` per injector
**black:** Default settings (88 char lines), must pass `black --check .`
**flake8:** Max line 120, ignores E,W categories (focuses on F-syntax, B-bugbear). Config: `.flake8`
**Testing:** Python `unittest`, run `python -m unittest` from injector root. Tests in `test/` dirs.
**Versioning:** Current 2.0.10 (pyoaev). Versions in requirements.txt, docker-compose.yml, __version__ vars.

## GitHub Workflows

**PR Title Format (validate-pr-title.yml):** `[category] type(scope): description (#123)`
- Types: feat|fix|chore|docs|style|refactor|perf|test|build|ci|revert
- Example: `[nuclei] feat: add scanner` or `[nmap/contracts] fix(scan): correct command (#42)`

**Release (release.yml):** Runs scripts/release.py to update versions across repo via grep/sed, creates tags, generates release notes with gren.

## Key Dependencies

**All injectors:** pyoaev==2.0.10
**nuclei Docker:** Nuclei 3.4.3 binary, Python 3.13-alpine
**nmap Docker:** nmap + jc CLI tools, Python 3.13-alpine  
**aws Docker:** Pacu (pip), AWS CLI (pip), Python 3.11-slim (NOT Alpine)
**http-query Docker:** Python 3.13-alpine, no external tools

## Pre-Commit Checklist

1. **Format code:** `isort --profile black .` then `black .`
2. **Lint:** `flake8 --ignore=E,W .` must pass
3. **Test:** Run `python -m unittest` for modified injectors
4. **Docker (if deps changed):** Test build with correct --build-context for nmap/nuclei
5. **Review diff:** No unintended changes, especially in other injectors
6. **Check commits:** No build artifacts, venv, IDE files (.gitignore configured)

## Configuration Pattern

Each injector has `config.yml.sample`:
- openaev.url - OpenAEV platform URL
- openaev.token - Auth token
- injector.id - UUID instance ID
- injector.name - Display name
- injector.log_level - info/warn/error/debug

## Critical Notes

- **Shared code:** Only nmap/nuclei use `injector_common`. http-query/aws are standalone.
- **Entry points:** Named `openaev_<name>.py` in each injector
- **Module isolation:** Each injector is independent with own tests
- **pyoaev consistency:** Keep version same across all injectors unless specifically updating
- **Trust these instructions:** Validated against actual codebase. Search only if incomplete/incorrect.
