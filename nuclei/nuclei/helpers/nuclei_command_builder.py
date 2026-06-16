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


class NucleiCommandBuilder:
    # See https://docs.projectdiscovery.io/opensource/nuclei/running#nuclei-flags
    TAG_MAP = {
        CVE_SCAN_CONTRACT: "cve",
        CLOUD_SCAN_CONTRACT: "cloud",
        MISCONFIG_SCAN_CONTRACT: "misconfiguration",
        EXPOSURE_SCAN_CONTRACT: "exposure",
        PANEL_SCAN_CONTRACT: "panel",
        XSS_SCAN_CONTRACT: "xss",
        WORDPRESS_SCAN_CONTRACT: "wordpress",
        HTTP_SCAN_CONTRACT: "http",
    }

    def __init__(
        self, nuclei_configs, contract_id: str, content: dict, targets: list[str]
    ):
        self.args = []
        self.nuclei_configs = nuclei_configs
        self.contract_id = contract_id
        self.content = content
        self.targets = targets

    def build(self):
        build = (
            self._with_nuclei()
            ._with_configs()
            ._with_tags()
            ._with_templates()
            ._with_options()
            ._with_jsonl_output()
        )
        return build._to_args()

    def _to_args(self):
        return list(self.args)

    def _with_nuclei(self):
        self.args += ["nuclei"]
        return self

    # def _with_targets(self):
    #     # Target URLs/hosts to scan.
    #     # Nuclei Flags: -u, -target
    #     for target in self.targets:
    #         self.args += ["-u", target]
    #     return self

    def _with_tags(self):
        # Templates to run based on tags.
        # Nuclei Flags: -tags
        if self.contract_id in self.TAG_MAP:
            self.args += ["-tags", self.TAG_MAP[self.contract_id]]
        return self

    def _with_templates(self):
        template = self.content.get("template")
        template_path = self.content.get("template_path")
        # List of template or template directory to run.
        # Nuclei Flags: -t, -templates
        if template:
            self.args += ["-templates", template]
        if template_path:
            self.args += ["-templates", template_path]

        if self.contract_id == TEMPLATE_SCAN_CONTRACT:
            # Add -t "/" only if no template is specified in the content
            if not (self.content.get("template") or self.content.get("template_path")):
                self.args += ["-templates", "/"]
        return self

    def _with_options(self):
        options = self.content.get("options")
        if options:
            self.args += [options]
        return self

    def _with_jsonl_output(self):
        # Write output in JSONL(ines) format.
        # Nuclei Flags: -j, -jsonl
        self.args += ["-jsonl"]
        return self

    def _with_configs(self):
        self._add_concurrency()
        self._add_bulk_size()
        self._add_rate_limit()
        self._add_timeout()
        self._add_retries()
        self._add_max_host_error()
        self._add_scan_strategy()
        self._add_response_size_read()
        self._add_response_size_save()
        self._add_exclude_type()
        self._add_exclude_severity()
        return self

    def _add_concurrency(self):
        # Maximum number of templates to be executed in parallel.
        # Nuclei Flags: -c, -concurrency
        self.args += [
            "-concurrency",
            str(self.nuclei_configs.templates_parallelism),
        ]
        return self

    def _add_bulk_size(self):
        # Maximum number of hosts to be analyzed in parallel per template.
        # Nuclei Flags: -bs, -bulk-size
        self.args += [
            "-bulk-size",
            str(self.nuclei_configs.hosts_parallelism_per_template),
        ]
        return self

    def _add_rate_limit(self):
        # Maximum number of requests to send per second.
        # Nuclei Flags: -rl, -rate-limit
        self.args += [
            "-rate-limit",
            str(self.nuclei_configs.max_requests_per_second),
        ]
        return self

    def _add_timeout(self):
        # Time to wait in seconds before timeout.
        # Nuclei Flags: -timeout
        self.args += [
            "-timeout",
            str(self.nuclei_configs.timeout),
        ]
        return self

    def _add_retries(self):
        # Number of times to retry a failed request.
        # Nuclei Flags: -retries
        self.args += [
            "-retries",
            str(self.nuclei_configs.retries),
        ]
        return self

    def _add_max_host_error(self):
        # Max errors for a host before skipping from scan.
        # Nuclei Flags: -mhe, -max-host-error
        self.args += [
            "-max-host-error",
            str(self.nuclei_configs.max_host_error),
        ]
        return self

    def _add_scan_strategy(self):
        # Strategy to use while scanning (auto, host-spray, template-spray).
        # Nuclei Flags: -ss, -scan-strategy
        self.args += [
            "-scan-strategy",
            self.nuclei_configs.scan_strategy,
        ]
        return self

    def _add_response_size_read(self):
        # Max response size to read in bytes.
        # Nuclei Flags: -rsr, -response-size-read
        self.args += [
            "-response-size-read",
            str(self.nuclei_configs.response_size_read),
        ]
        return self

    def _add_response_size_save(self):
        # Max response size to save in bytes.
        # Nuclei Flags: -rss, -response-size-save
        self.args += [
            "-response-size-save",
            str(self.nuclei_configs.response_size_save),
        ]
        return self

    def _add_exclude_type(self):
        # Templates to exclude based on protocol type.
        # Nuclei Flags: -ept, -exclude-type
        if self.nuclei_configs.exclude_type:
            self.args += [
                "-exclude-type",
                ",".join(self.nuclei_configs.exclude_type),
            ]
        return self

    def _add_exclude_severity(self):
        # Templates to exclude based on severity.
        # Nuclei Flags: -es, -exclude-severity
        if self.nuclei_configs.exclude_severity:
            self.args += [
                "-exclude-severity",
                ",".join(self.nuclei_configs.exclude_severity),
            ]
        return self
