#!/bin/bash
# Common test script for all OpenAEV injectors.
# Usage:
#   ./run_test.sh <injector_dir>          Run tests for a single injector
#   ./run_test.sh <dir1> <dir2> ...        Run tests for multiple injectors
#   ./run_test.sh                           Auto-discover and run all injector tests
#
# Environment variables:
#   RELEASE_REF       Base branch for git diff (default: main)
#   GITHUB_REF_NAME   Current branch name (GitHub Actions)
#   CIRCLE_BRANCH     Current branch name (CircleCI)

set -e

RELEASE_REF="${RELEASE_REF:-main}"
BRANCH="${CIRCLE_BRANCH:-${GITHUB_REF_NAME:-$RELEASE_REF}}"
REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"

# Determine pyoaev git branch
if [ "$BRANCH" = "main" ]; then
  PYOAEV_BRANCH="main"
else
  PYOAEV_BRANCH="release/current"
fi

# Discover injectors with test directories
discover_injectors() {
  find "$REPO_ROOT" -maxdepth 2 \( -name "test" -o -name "tests" \) -type d \
    | sed "s|^$REPO_ROOT/||; s|/test.*||" \
    | sort -u
}

# Check whether a pyproject.toml uses poetry as its build backend
uses_poetry() {
  local pyproject="$1/pyproject.toml"
  [ -f "$pyproject" ] && grep -q 'poetry' "$pyproject" 2>/dev/null
}

# Detect install arguments for a project's pyproject.toml
get_install_args() {
  local pyproject="$1/pyproject.toml"
  local args=""

  # Check for poetry group "test" containing test deps
  if grep -q '\[tool\.poetry\.group\.test' "$pyproject" 2>/dev/null; then
    args="$args --with test"
  # Check if dev optional-dependencies contain pytest
  elif sed -n '/\[project\.optional-dependencies\]/,/^\[/p' "$pyproject" 2>/dev/null | grep -q 'pytest'; then
    args="$args --extras dev"
  # Check if poetry dev group contains pytest
  elif grep -q '\[tool\.poetry\.group\.dev' "$pyproject" 2>/dev/null; then
    if sed -n '/\[tool\.poetry\.group\.dev/,/^\[/p' "$pyproject" | grep -q 'pytest'; then
      args="$args --with dev"
    fi
  fi

  echo "$args"
}

# Detect whether the injector uses pytest or unittest
uses_pytest() {
  local injector_dir="$1"
  local pyproject="$injector_dir/pyproject.toml"

  if grep -q '\[tool\.pytest' "$pyproject" 2>/dev/null; then
    return 0
  fi

  if [ -f "$injector_dir/tests/conftest.py" ] || [ -f "$injector_dir/test/conftest.py" ]; then
    return 0
  fi

  if grep -q 'pytest' "$pyproject" 2>/dev/null; then
    return 0
  fi

  return 1
}

# Detect test directory
detect_test_dir() {
  local injector_dir="$1"
  if [ -d "$injector_dir/test" ]; then
    echo "test"
  elif [ -d "$injector_dir/tests" ]; then
    echo "tests"
  fi
}

# Run tests for a single injector
run_injector_tests() {
  local injector="$1"
  local injector_dir="$REPO_ROOT/$injector"

  echo "==========================================="
  echo "Processing: $injector"
  echo "==========================================="

  cd "$injector_dir"

  local test_dir
  test_dir=$(detect_test_dir "$injector_dir")

  if uses_poetry "$injector_dir"; then
    echo "🔄 Running tests for $injector (poetry)"

    command -v poetry >/dev/null 2>&1 || pip install -q poetry==2.3.2
    poetry config installer.re-resolve false 2>/dev/null || true

    echo "→ poetry install"
    local install_args
    install_args=$(get_install_args "$injector_dir")
    poetry install $install_args

    echo "→ Installing pyoaev from branch $PYOAEV_BRANCH"
    poetry run pip install --force-reinstall -q \
      "git+https://github.com/OpenAEV-Platform/client-python.git@$PYOAEV_BRANCH"

    poetry run pip install -q coverage

    local test_rc=0
    if uses_pytest "$injector_dir"; then
      echo "→ Running pytest"
      poetry run python -m coverage run -m pytest -q -rA || test_rc=$?
    else
      echo "→ Running unittest"
      poetry run python -m coverage run -m unittest discover -s "$test_dir" -v || test_rc=$?
    fi

    poetry run python -m coverage xml -o coverage.xml || true

  else
    echo "🔄 Running tests for $injector (setuptools)"

    pip install -q -e .

    echo "→ Installing pyoaev from branch $PYOAEV_BRANCH"
    pip install --force-reinstall -q \
      "git+https://github.com/OpenAEV-Platform/client-python.git@$PYOAEV_BRANCH"

    pip install -q coverage

    local test_rc=0
    if uses_pytest "$injector_dir"; then
      echo "→ Running pytest"
      python -m coverage run -m pytest -q -rA || test_rc=$?
    else
      echo "→ Running unittest"
      python -m coverage run -m unittest discover -s "$test_dir" -v || test_rc=$?
    fi

    python -m coverage xml -o coverage.xml || true
  fi

  cd "$REPO_ROOT"
  return $test_rc
}

# --- Main ---

if [ $# -gt 0 ]; then
  injectors="$*"
else
  injectors=$(discover_injectors)
fi

exit_code=0
for injector in $injectors; do
  if run_injector_tests "$injector"; then
    echo "✅ $injector tests passed"
  else
    echo "❌ $injector tests FAILED"
    exit_code=1
  fi
done

exit $exit_code
