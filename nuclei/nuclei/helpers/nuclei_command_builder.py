from typing import Dict, List

from nuclei.nuclei_contracts.nuclei_constants import (CLOUD_SCAN_CONTRACT,
                                                      CVE_SCAN_CONTRACT,
                                                      EXPOSURE_SCAN_CONTRACT,
                                                      HTTP_SCAN_CONTRACT,
                                                      MISCONFIG_SCAN_CONTRACT,
                                                      PANEL_SCAN_CONTRACT,
                                                      TEMPLATE_SCAN_CONTRACT,
                                                      WORDPRESS_SCAN_CONTRACT,
                                                      XSS_SCAN_CONTRACT)


class NucleiCommandBuilder:
    TAG_MAP = {
        CLOUD_SCAN_CONTRACT: "cloud",
        MISCONFIG_SCAN_CONTRACT: "misconfiguration",
        EXPOSURE_SCAN_CONTRACT: "exposure",
        PANEL_SCAN_CONTRACT: "panel",
        XSS_SCAN_CONTRACT: "xss",
        WORDPRESS_SCAN_CONTRACT: "wordpress",
        HTTP_SCAN_CONTRACT: "http",
    }

    def build_args(
        self, contract_id: str, content: Dict, targets: List[str]
    ) -> List[str]:
        args = ["nuclei"]
        json_output = False

        if contract_id == CVE_SCAN_CONTRACT:
            args += ["-tags", "cve", "-j"]
            json_output = True
        elif contract_id in self.TAG_MAP:
            args += ["-tags", self.TAG_MAP[contract_id]]
        elif contract_id == TEMPLATE_SCAN_CONTRACT:
            # Add -t "/" only if no template is specified in the content
            if not (content.get("template") or content.get("template_path")):
                args += ["-t", "/"]

        template = content.get("template") or content.get("template_path")
        if template:
            args += ["-t", template]
            if "cve" in template.lower() and not json_output:
                args += ["-j"]

        for target in targets:
            args += ["-u", target]

        return args
