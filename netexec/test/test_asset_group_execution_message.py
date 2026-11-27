import sys
import time
from importlib.abc import Loader, MetaPathFinder
from importlib.machinery import ModuleSpec
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import MagicMock, patch


class _PyoaevLoader(Loader):
    def create_module(self, spec):
        module = MagicMock()
        module.__name__ = spec.name
        module.__package__ = spec.name
        module.__path__ = []
        module.__spec__ = spec
        return module

    def exec_module(self, module):
        return None


class _PyoaevFinder(MetaPathFinder):
    def find_spec(self, fullname, path, target=None):
        if fullname == "pyoaev" or fullname.startswith("pyoaev."):
            return ModuleSpec(fullname, _PyoaevLoader(), is_package=True)
        return None


_finder = _PyoaevFinder()
sys.meta_path.insert(0, _finder)
try:
    from netexec.openaev_netexec import OpenAEVNetExecInjector
finally:
    sys.meta_path.remove(_finder)
    for _name in list(sys.modules):
        if _name == "pyoaev" or _name.startswith("pyoaev."):
            del sys.modules[_name]


class _Logger:
    def info(self, *args, **kwargs):
        return None

    def warning(self, *args, **kwargs):
        return None

    def error(self, *args, **kwargs):
        return None


def _inject_message():
    return {
        "injection": {
            "inject_id": "inj-1",
            "inject_injector_contract": {"injector_contract_id": "netexec_smb"},
            "inject_content": {
                "target_selector": "asset-groups",
                "target_property_selector": "hostname",
                "username": "alice",
                "expectations": [],
            },
        },
        "assetGroups": [{"asset_group_id": "g1", "asset_group_name": "Finance"}],
        "assets": [
            {
                "asset_id": "a1",
                "asset_name": "host1",
                "asset_hostname": "host1.example",
            }
        ],
    }


class AssetGroupExecutionMessageTest(TestCase):
    def test_asset_group_inject_reports_the_group_name(self):
        injector = OpenAEVNetExecInjector.__new__(OpenAEVNetExecInjector)
        callbacks = []

        class InjectApi:
            def execution_callback(self, **kwargs):
                callbacks.append(kwargs)

        injector.helper = SimpleNamespace(
            injector_logger=_Logger(),
            api=SimpleNamespace(inject=InjectApi()),
        )
        injector._pre_execution_compile = lambda targets: ({}, [])
        injector.parser = SimpleNamespace(
            parse=lambda *args, **kwargs: {"outputs": {}, "message": ""}
        )

        with (
            patch(
                "netexec.openaev_netexec.execute_netexec",
                return_value=("", "", 0),
            ),
            patch("netexec.openaev_netexec.send_per_target_traces"),
        ):
            injector.execute(time.time(), _inject_message())

        self.assertEqual(len(callbacks), 1)
        message = callbacks[0]["data"]["execution_message"]
        self.assertIn("Finance", message)
        self.assertIn("host1.example", message)
