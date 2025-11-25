from typing import Dict

from injector_common.injector_common.targets import TargetExtractionResult


class NmapOutputParser:
    def parse(data: Dict, result: str, target_results: TargetExtractionResult) -> Dict:
        """Parse nmap results and extract open ports."""
        asset_list = list(target_results.ip_to_asset_id_map.values())
        targets = target_results.targets

        run = result["nmaprun"]
        if not isinstance(run["host"], list):
            run["host"] = [run["host"]]

        ports_scans_results = []
        ports_results = []
        for idx, host in enumerate(run["host"]):
            if "ports" in host and "port" in host["ports"]:
                for port in host["ports"]["port"]:
                    if port["state"]["@state"] == "open":
                        ports_results.append(int(port["@portid"]))
                        port_result = {
                            "port": int(port["@portid"]),
                            "service": port["service"]["@name"],
                        }
                        if data["injection"]["inject_content"]["target_selector"] in [
                            "assets",
                            "asset-groups",
                        ]:
                            port_result["asset_id"] = asset_list[idx]
                            port_result["host"] = host["address"]["@addr"]
                        else:
                            port_result["asset_id"] = None
                            port_result["host"] = targets[idx]
                        ports_scans_results.append(port_result)

        return {
            "message": "Targets successfully scanned ("
            + str(len(ports_results))
            + " ports found )",
            "outputs": {"scan_results": ports_scans_results, "ports": ports_results},
        }
