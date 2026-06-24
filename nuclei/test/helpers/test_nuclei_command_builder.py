from unittest.mock import Mock

import pytest

from nuclei.helpers.nuclei_command_builder import NucleiCommandBuilder
from nuclei.nuclei_contracts.nuclei_constants import (
    CLOUD_SCAN_CONTRACT,
    CVE_SCAN_CONTRACT,
    EXPOSURE_SCAN_CONTRACT,
    HTTP_SCAN_CONTRACT,
    MISCONFIG_SCAN_CONTRACT,
    PANEL_SCAN_CONTRACT,
    TEMPLATE_SCAN_CONTRACT,
    WORDPRESS_SCAN_CONTRACT,
    XSS_SCAN_CONTRACT,
)


@pytest.fixture
def nuclei_configs():
    config = Mock()
    config.scan_strategy = "host-spray"
    config.templates_parallelism = 5
    config.hosts_parallelism_per_template = 5
    config.max_requests_per_second = 50
    config.timeout = 10
    config.retries = 1
    config.max_host_error = 30
    config.response_size_read = 1048576
    config.response_size_save = 1048576
    config.exclude_type = ["headless"]
    config.exclude_severity = ["info"]
    return config


BASE_ARGS = [
    "nuclei",
    "-concurrency",
    "5",
    "-bulk-size",
    "5",
    "-rate-limit",
    "50",
    "-timeout",
    "10",
    "-retries",
    "1",
    "-max-host-error",
    "30",
    "-scan-strategy",
    "host-spray",
    "-response-size-read",
    "1048576",
    "-response-size-save",
    "1048576",
    "-exclude-type",
    "headless",
    "-exclude-severity",
    "info",
]


@pytest.mark.parametrize(
    "contract_id, content, extra_args",
    [
        (CVE_SCAN_CONTRACT, {}, ["-tags", "cve", "-jsonl"]),
        (
            CVE_SCAN_CONTRACT,
            {"options": "-severity high -silent"},
            ["-tags", "cve", "-severity", "high", "-silent", "-jsonl"],
        ),
        (CLOUD_SCAN_CONTRACT, {}, ["-tags", "cloud", "-jsonl"]),
        (MISCONFIG_SCAN_CONTRACT, {}, ["-tags", "misconfiguration", "-jsonl"]),
        (EXPOSURE_SCAN_CONTRACT, {}, ["-tags", "exposure", "-jsonl"]),
        (PANEL_SCAN_CONTRACT, {}, ["-tags", "panel", "-jsonl"]),
        (XSS_SCAN_CONTRACT, {}, ["-tags", "xss", "-jsonl"]),
        (WORDPRESS_SCAN_CONTRACT, {}, ["-tags", "wordpress", "-jsonl"]),
        (HTTP_SCAN_CONTRACT, {}, ["-tags", "http", "-jsonl"]),
        (TEMPLATE_SCAN_CONTRACT, {}, ["-templates", "/", "-jsonl"]),
        (
            HTTP_SCAN_CONTRACT,
            {"template": "cves/2021/1234.yaml"},
            ["-tags", "http", "-templates", "cves/2021/1234.yaml", "-jsonl"],
        ),
    ],
    ids=[
        "Contract-CVE",
        "Contract-CVE-WITH-OPTIONS",
        "Contract-CLOUD",
        "Contract-MISCONFIG",
        "Contract-EXPOSURE",
        "Contract-PANEL",
        "Contract-XSS",
        "Contract-WORDPRESS",
        "Contract-HTTP",
        "Contract-TEMPLATE",
        "Contract-HTTP-TEMPLATE",
    ],
)
def test_nuclei_builder(nuclei_configs, contract_id, content, extra_args):
    nuclei_args = NucleiCommandBuilder(
        nuclei_configs=nuclei_configs,
        contract_id=contract_id,
        content=content,
        targets=["http://example.com", "http://another-example.com"],
    ).build()

    expected_args = BASE_ARGS + extra_args
    assert nuclei_args == expected_args
