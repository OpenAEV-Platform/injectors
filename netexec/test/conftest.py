"""Mock pyoaev modules before any netexec contracts code is imported.

The installed pyoaev version may not match the one used at development time.
We replace the relevant pyoaev sub-modules with MagicMock-based stubs so that
pure-logic tests (parse_contract_id, build_command, etc.) can run without the
real pyoaev SDK.
"""

import sys
from unittest.mock import MagicMock

# Build a module-like MagicMock that allows arbitrary attribute access and
# `from module import SomeClass` statements.
for mod_path in (
    "pyoaev",
    "pyoaev.contracts",
    "pyoaev.contracts.contract_config",
    "pyoaev.contracts.contract_output",
    "pyoaev.contracts.contract_utils",
    "pyoaev.security_domain",
    "pyoaev.security_domain.types",
    "pyoaev.helpers",
    "pyoaev.apis",
    "pyoaev.apis.inputs",
    "pyoaev.apis.inputs.search",
    "pyoaev.client",
    "pyoaev.config",
):
    sys.modules[mod_path] = MagicMock()
