import unittest
from unittest.mock import patch, sentinel

import nmap.helpers.nmap_process as module


@patch.object(module, "subprocess")
class TestNmapProcess(unittest.TestCase):
    def test_nmap_execute(self, m_subprocess):
        args = sentinel.args

        module.NmapProcess.nmap_execute(args)

        m_subprocess.run.assert_called_once_with(
            sentinel.args, check=True, capture_output=True
        )
