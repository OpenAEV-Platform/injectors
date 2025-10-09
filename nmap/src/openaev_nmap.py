import json
import subprocess
import time
from typing import Dict

from common.pagination import Pagination
from pyoaev.helpers import OpenAEVConfigHelper, OpenAEVInjectorHelper

from contracts_nmap import (FIN_SCAN_CONTRACT, TCP_CONNECT_SCAN_CONTRACT,
                            TCP_SYN_SCAN_CONTRACT, NmapContracts)


class OpenAEVNmap:
    def __init__(self):
        self.config = OpenAEVConfigHelper(
            __file__,
            {
                # API information
                "openaev_url": {"env": "OPENAEV_URL", "file_path": ["openaev", "url"]},
                "openaev_token": {
                    "env": "OPENAEV_TOKEN",
                    "file_path": ["openaev", "token"],
                },
                # Config information
                "injector_id": {"env": "INJECTOR_ID", "file_path": ["injector", "id"]},
                "injector_name": {
                    "env": "INJECTOR_NAME",
                    "file_path": ["injector", "name"],
                },
                "injector_type": {
                    "env": "INJECTOR_TYPE",
                    "file_path": ["injector", "type"],
                    "default": "openaev_nmap",
                },
                "injector_contracts": {"data": NmapContracts.build_contract()},
            },
        )
        self.helper = OpenAEVInjectorHelper(
            self.config, open("img/icon-nmap.png", "rb")
        )

    def nmap_execution(self, start: float, data: Dict) -> Dict:
        inject_id = data["injection"]["inject_id"]
        contract_id = data["injection"]["inject_injector_contract"]["convertedContent"][
            "contract_id"
        ]
        nmap_args = ["nmap", "-Pn"]
        if contract_id == TCP_SYN_SCAN_CONTRACT:
            nmap_args.append("-sS")
        elif contract_id == TCP_CONNECT_SCAN_CONTRACT:
            nmap_args.append("-sT")
        elif contract_id == FIN_SCAN_CONTRACT:
            nmap_args.append("-sF")
        nmap_args = nmap_args + ["-oX", "-"]

        asset_list = []
        if data["injection"]["inject_content"]["target_selector"] == "assets":
            target_property_selector = data["injection"]["inject_content"][
                "target_property_selector"
            ]
            for asset in data["assets"]:
                asset_list.append(asset["asset_id"])
                if target_property_selector == "seen_ip":
                    nmap_args.append(asset["endpoint_seen_ip"])
                elif target_property_selector == "local_ip":
                    if len(asset["endpoint_ips"]) == 0:
                        raise ValueError("No IP found for this endpoint")
                    nmap_args.append(asset["endpoint_ips"][0])
                else:
                    nmap_args.append(asset["endpoint_hostname"])
        else:
            for target in data["injection"]["inject_content"]["targets"].split(","):
                asset_list.append(target.strip())
                nmap_args.append(target.strip())

        self.helper.injector_logger.info(
            "Executing nmap with command: " + " ".join(nmap_args)
        )
        callback_data = {
            "execution_message": " ".join(nmap_args),
            "execution_status": "INFO",
            "execution_duration": int(time.time() - start),
            "execution_action": "command_execution",
        }
        self.helper.api.inject.execution_callback(
            inject_id=inject_id, data=callback_data
        )
        nmap = subprocess.run(
            nmap_args,
            check=True,
            capture_output=True,
        )
        jc = subprocess.run(
            ["jc", "--xml", "-p"], input=nmap.stdout, capture_output=True
        )
        result = json.loads(jc.stdout.decode("utf-8").strip())
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

    def process_message(self, data: Dict) -> None:
        start = time.time()
        inject_id = data["injection"]["inject_id"]
        # Notify API of reception and expected number of operations
        reception_data = {"tracking_total_count": 1}

        target2execute = Pagination.fetch_all_targets(self.helper)
        print(target2execute)

        self.helper.api.inject.execution_reception(
            inject_id=inject_id, data=reception_data
        )
        # Execute inject
        try:
            execution_result = self.nmap_execution(start, data)
            callback_data = {
                "execution_message": execution_result["message"],
                "execution_output_structured": json.dumps(execution_result["outputs"]),
                "execution_status": "SUCCESS",
                "execution_duration": int(time.time() - start),
                "execution_action": "complete",
            }
            self.helper.api.inject.execution_callback(
                inject_id=inject_id, data=callback_data
            )
        except Exception as e:
            callback_data = {
                "execution_message": str(e),
                "execution_status": "ERROR",
                "execution_duration": int(time.time() - start),
                "execution_action": "complete",
            }
            self.helper.api.inject.execution_callback(
                inject_id=inject_id, data=callback_data
            )

    # Start the main loop
    def start(self):
        self.helper.listen(message_callback=self.process_message)


if __name__ == "__main__":
    openAEVNmap = OpenAEVNmap()
    openAEVNmap.start()
