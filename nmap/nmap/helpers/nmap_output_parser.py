from injector_common.targets import TargetExtractionResult


class NmapOutputParser:
    @staticmethod
    def parse(data: dict, result: dict, target_results: TargetExtractionResult) -> dict:
        """Parse nmap results and extract open ports."""
        asset_list = list(target_results.ip_to_asset_id_map.values())
        targets = target_results.targets or []
        selector_is_asset = data["injection"]["inject_content"]["target_selector"] in [
            "assets",
            "asset-groups",
        ]

        run = result["nmaprun"]
        if not isinstance(run["host"], list):
            run["host"] = [run["host"]]

        ports_scans_results = []
        ports_results = []

        for idx, host in enumerate(run["host"]):
            for port in host.get("ports", {}).get("port", []):
                if port.get("state", {}).get("@state") == "open":
                    portid = int(port["@portid"])
                    ports_results.append(portid)

                    port_result = {
                        "port": portid,
                        "service": port.get("service", {}).get("@name", "missing name"),
                        "asset_id": None,
                        "host": None,
                    }
                    if selector_is_asset:
                        port_result["asset_id"] = asset_list[idx]
                        port_result["host"] = host.get("address", {}).get(
                            "@addr", "missing IP"
                        )
                    elif idx < len(targets):
                        port_result["host"] = targets[idx]

                    ports_scans_results.append(port_result)

        return {
            "message": f"Targets successfully scanned ({len(ports_results)} ports found)",
            "outputs": {"scan_results": ports_scans_results, "ports": ports_results},
        }
