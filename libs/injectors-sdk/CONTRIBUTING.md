# Contributing to injectors-sdk

injectors-sdk runs on the
[xtm-oaev-sdk contributing guide](https://github.com/OpenAEV-Platform/client-python/blob/main/libs/xtm-oaev-sdk/CONTRIBUTING.md)
for the layering, seams, tests and TDRs, and on the repository's
[CONTRIBUTING.md](../../CONTRIBUTING.md) for commits and pull requests. This page only
covers where it differs.

## Set up

On Python 3.12 or later, with `client-python` checked out right next to this repository:

```bash
cd libs/injectors-sdk
pip install -e ../../../client-python/libs/xtm-oaev-sdk -e .
```

No local `client-python`? Pull `xtm-oaev-sdk` straight from git:

```bash
pip install "xtm-oaev-sdk @ git+https://github.com/OpenAEV-Platform/client-python.git@<ref>#subdirectory=libs/xtm-oaev-sdk"
```

## Run the checks

```bash
python -m pytest test   # from libs/injectors-sdk
black libs/injectors-sdk && isort --profile black libs/injectors-sdk && flake8 --ignore=E,W libs/injectors-sdk   # from the repository root
```

The repository's pre-commit configuration pins isort 5.10.1, which won't install on
current Python, and its isort hook says `arts:` where it means `args:`. Until someone
fixes it, run the three tools by hand, as above. The repository CI does not run the
injectors-sdk tests yet. That job is yours: run them before every change.

## What is specific here

- injectors-sdk reaches xtm-oaev-sdk through its package root only, and never imports
  `pyoaev`, `thefuzz` or `requests`. `test/test_boundaries.py` keeps it honest
  ([injectors-sdk-builds-on-xtm-oaev-sdk-public-api-only](docs/tdr/injectors-sdk-builds-on-xtm-oaev-sdk-public-api-only.tdr.md)).
- Need something new in xtm-oaev-sdk? That change starts in `client-python`, not here:
  injectors-sdk depends on `xtm-oaev-sdk (>=0.1.0,<0.2.0)`.
- Seam changes bump the `helpers` `SEAM_VERSION` and land in [CHANGELOG.md](CHANGELOG.md).
  Regenerate the seam golden in the same change, from `libs/injectors-sdk`:
  `python test/seam/generate_seam_golden.py`. Until then, `test/seam/test_seam_golden.py`
  fails on every seam object added, removed or changed. Same golden as xtm-oaev-sdk:
  [its guide](https://github.com/OpenAEV-Platform/client-python/blob/main/libs/xtm-oaev-sdk/CONTRIBUTING.md#seam-golden-testseam)
  covers what a fingerprint sees and how to read a failure.
- Commits carry the `injectors-sdk` scope:
  `:recycle: refactor(injectors-sdk): enhancing port-adapter public boundaries`.
- The decisions that belong to this SDK alone are in [docs/tdr/TDR_ToC.md](docs/tdr/TDR_ToC.md).
