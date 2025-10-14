from unittest import TestCase

from nuclei.helpers.nuclei_command_builder import NucleiCommandBuilder
from nuclei.nuclei_contracts.nuclei_constants import (
    CLOUD_SCAN_CONTRACT,
    CVE_SCAN_CONTRACT,
    HTTP_SCAN_CONTRACT,
    TEMPLATE_SCAN_CONTRACT,
)


class NucleiCommandBuilderTest(TestCase):

    def test_cve_contract(self):
        builder = NucleiCommandBuilder()
        targets = ["https://example.com"]
        args = builder.build_args(CVE_SCAN_CONTRACT, {}, targets)
        expected_args = ["nuclei", "-tags", "cve", "-j", "-u", "https://example.com"]
        assert args == expected_args

    def test_cloud_contract(self):
        builder = NucleiCommandBuilder()
        args = builder.build_args(CLOUD_SCAN_CONTRACT, {}, ["https://example.com"])
        expected_args = ["nuclei", "-tags", "cloud", "-u", "https://example.com"]
        assert args == expected_args

    def test_scan_contract(self):
        builder = NucleiCommandBuilder()
        args = builder.build_args(TEMPLATE_SCAN_CONTRACT, {}, ["https://example.com"])
        expected_args = ["nuclei", "-t", "/", "-u", "https://example.com"]
        assert args == expected_args

    def test_template_contract_with_template_and_cve(self):
        builder = NucleiCommandBuilder()
        content = {"template": "cves/2021/1234.yaml"}
        targets = ["https://example.com"]
        args = builder.build_args(HTTP_SCAN_CONTRACT, content, targets)
        expected_args = [
            "nuclei",
            "-tags",
            "http",
            "-t",
            "cves/2021/1234.yaml",
            "-j",
            "-u",
            "https://example.com",
        ]
        assert args == expected_args
