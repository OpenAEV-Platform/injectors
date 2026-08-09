from unittest import mock

from nuclei.helpers.nuclei_process import NucleiProcess


@mock.patch("nuclei.helpers.nuclei_process.subprocess.run")
def test_nuclei_update_templates_passes_timeout(m_run):
    # The refresh must bound the update subprocess so a hung
    # "nuclei -update-templates" cannot hold the writer lock forever.
    NucleiProcess.nuclei_update_templates(timeout=123)

    m_run.assert_called_once_with(
        ["nuclei", "-update-templates"], check=True, timeout=123
    )


@mock.patch("nuclei.helpers.nuclei_process.subprocess.run")
def test_nuclei_update_templates_defaults_to_no_timeout(m_run):
    NucleiProcess.nuclei_update_templates()

    m_run.assert_called_once_with(
        ["nuclei", "-update-templates"], check=True, timeout=None
    )


@mock.patch("nuclei.helpers.nuclei_process.subprocess.run")
def test_nuclei_execute_passes_timeout(m_run):
    # The scan ceiling is a hard timeout on the whole run (Nuclei's own
    # -timeout is per-request only).
    NucleiProcess.nuclei_execute(["nuclei", "-jsonl"], b"1.1.1.1\n", timeout=540)

    m_run.assert_called_once_with(
        ["nuclei", "-jsonl"],
        input=b"1.1.1.1\n",
        capture_output=True,
        check=True,
        timeout=540,
    )
