import json
import re
from collections import defaultdict
from typing import Dict


class NmapOutputParser:
    def parse(data: Dict, result: str, asset_list: []) -> Dict:
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
                        if (
                            data["injection"]["inject_content"]["target_selector"]
                            == "assets"
                        ):
                            port_result["asset_id"] = asset_list[idx]
                            port_result["host"] = host["address"]["@addr"]
                        else:
                            port_result["asset_id"] = None
                            port_result["host"] = asset_list[idx]
                        ports_scans_results.append(port_result)

        return {
            "message": "Targets successfully scanned ("
            + str(len(ports_results))
            + " ports found )",
            "outputs": {"scan_results": ports_scans_results, "ports": ports_results},
        }
