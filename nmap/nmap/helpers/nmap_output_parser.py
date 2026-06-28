from lxml import objectify

from injector_common.targets import TargetExtractionResult


class NmapOutputParser:
    @staticmethod
    def xmlparse(
        stdout: bytes, selector_key: str, target_results: TargetExtractionResult
    ) -> dict:
        """Parse XML formatted nmap outputs and extract open ports."""
        xml_parser = objectify.makeparser(resolve_entities=False)
        xml_tree = objectify.fromstring(stdout, xml_parser)

        if xml_tree.tag != "nmaprun":
            raise ValueError("provided stdout does not match expected nmap XML output")

        asset_list = (
            list(target_results.ip_to_asset_id_map.values()) or []
        )  # list of IDs post asset-groups resolution
        targets = target_results.targets or []

        selector_is_asset = selector_key in ["assets", "asset-groups"]

        ports_scans_results = []
        ports_results = []

        for idx, host in enumerate(xml_tree.host):
            for port in host.ports.iterchildren(tag="port"):
                if port.state.get("state") == "open":
                    portid = int(port.get("portid"))
                    ports_results.append(portid)

                    port_result = {
                        "port": portid,
                        "service": port.service.get("name", "missing name"),
                        "asset_id": None,
                        "host": None,
                    }
                    if selector_is_asset:
                        port_result["asset_id"] = asset_list[idx]
                        port_result["host"] = host.address.get("addr", "missing IP")
                    elif idx < len(targets):
                        port_result["host"] = targets[idx]

                    ports_scans_results.append(port_result)

        return {
            "message": f"Targets successfully scanned ({len(ports_results)} ports found)",
            "outputs": {"scan_results": ports_scans_results, "ports": ports_results},
        }
