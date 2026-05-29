import unittest
from unittest.mock import MagicMock, patch, sentinel

import nmap.helpers.nmap_process as module


@patch.object(module, "subprocess")
class TestNmapProcess(unittest.TestCase):
    def test_nmap_execute(self, m_subprocess):
        args = sentinel.args

        module.NmapProcess.nmap_execute(args)

        m_subprocess.run.assert_called_once_with(
            sentinel.args, check=True, capture_output=True
        )

    def test_js_execute(self, m_subprocess):
        args = sentinel.args
        m_input = MagicMock()

        module.NmapProcess.js_execute(args, m_input)

        m_subprocess.run.assert_called_once_with(
            sentinel.args, input=m_input.stdout, capture_output=True
        )
