import sys
from importlib.abc import Loader, MetaPathFinder
from importlib.machinery import ModuleSpec
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import MagicMock


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


sys.meta_path.insert(0, _PyoaevFinder())

from netexec.openaev_netexec import OpenAEVNetExecInjector


class ProcessMessageErrorTest(TestCase):
    def test_execution_failure_is_logged_and_reported(self):
        injector = OpenAEVNetExecInjector.__new__(OpenAEVNetExecInjector)
        logged = []
        callbacks = []

        class Logger:
            def error(self, message, meta=None):
                logged.append(message)

        class InjectApi:
            def execution_reception(self, **kwargs):
                return None

            def execution_callback(self, **kwargs):
                callbacks.append(kwargs)

        injector.helper = SimpleNamespace(
            injector_logger=Logger(),
            api=SimpleNamespace(inject=InjectApi()),
        )

        def execute(start, data):
            raise RuntimeError("disk full")

        injector.execute = execute
        injector._process_message({"injection": {"inject_id": "inj-1"}})

        self.assertEqual(len(callbacks), 1)
        self.assertEqual(callbacks[0]["inject_id"], "inj-1")
        self.assertEqual(callbacks[0]["data"]["execution_status"], "ERROR")
        self.assertIn("disk full", callbacks[0]["data"]["execution_message"])
        self.assertEqual(logged, ["Execution failed for inject inj-1: disk full"])
