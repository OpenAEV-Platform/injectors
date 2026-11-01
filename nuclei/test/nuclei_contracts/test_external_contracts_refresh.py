import subprocess
import unittest
from unittest import mock
from unittest.mock import MagicMock

from nuclei.helpers.nuclei_process import NucleiProcess
from nuclei.nuclei_contracts.external_contracts import (
    ExternalContractsManager,
    ExternalContractsScheduler,
)


class TemplateRefreshTest(unittest.TestCase):
    """The periodic refresh must bound the update and never hold the writer
    lock past its own failure - a hung update degrades to best-effort so
    later scans (readers) are not blocked forever."""

    def _manager(self, templates_lock=None, timeout=None):
        return ExternalContractsManager(
            MagicMock(),
            "injector-id",
            MagicMock(),
            templates_lock=templates_lock,
            template_update_timeout=timeout,
        )

    @mock.patch.object(NucleiProcess, "nuclei_update_templates")
    def test_update_templates_holds_writer_lock_and_passes_timeout(self, m_update):
        lock = MagicMock()
        manager = self._manager(templates_lock=lock, timeout=300)

        manager._update_templates()

        lock.write.assert_called_once_with()
        m_update.assert_called_once_with(timeout=300)

    @mock.patch.object(NucleiProcess, "nuclei_update_templates")
    def test_update_templates_without_lock_still_bounds_the_update(self, m_update):
        manager = self._manager(templates_lock=None, timeout=300)

        manager._update_templates()

        m_update.assert_called_once_with(timeout=300)

    @mock.patch.object(NucleiProcess, "nuclei_update_templates")
    def test_update_templates_timeout_is_best_effort(self, m_update):
        # A hung update raises TimeoutExpired once the ceiling fires; the
        # writer-lock context manager releases as this unwinds, and the refresh
        # must swallow it (logged) instead of crashing the maintenance process.
        lock = MagicMock()
        m_update.side_effect = subprocess.TimeoutExpired(
            cmd="nuclei -update-templates", timeout=300
        )
        manager = self._manager(templates_lock=lock, timeout=300)

        manager._update_templates()  # must not raise

        lock.write.return_value.__enter__.assert_called_once()
        lock.write.return_value.__exit__.assert_called_once()
        manager._logger.error.assert_called()

    @mock.patch.object(NucleiProcess, "nuclei_update_templates")
    def test_update_templates_called_process_error_is_best_effort(self, m_update):
        m_update.side_effect = subprocess.CalledProcessError(
            returncode=1, cmd="nuclei -update-templates"
        )
        manager = self._manager(templates_lock=None, timeout=300)

        manager._update_templates()  # must not raise

        manager._logger.error.assert_called()

    def test_scheduler_wires_lock_and_timeout_into_the_manager(self):
        # The scheduler must hand both the shared templates lock and the update
        # ceiling to the manager the periodic refresh runs through.
        lock = MagicMock()
        scheduler = ExternalContractsScheduler(
            MagicMock(),
            "injector-id",
            86400,
            MagicMock(),
            templates_lock=lock,
            template_update_timeout=300,
        )

        self.assertIs(scheduler.manager._templates_lock, lock)
        self.assertEqual(scheduler.manager._template_update_timeout, 300)


if __name__ == "__main__":
    unittest.main()
