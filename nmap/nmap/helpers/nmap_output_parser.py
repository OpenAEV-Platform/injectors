from lxml import objectify

from injector_common.targets import TargetExtractionResult


SERVICE_PROBED = "probed"
SERVICE_GUESSED = "guessed"


class NmapOutputParser:
    @staticmethod
    def service_details(port) -> dict:
        """The service of an open port, labelled by how nmap identified it.

        Without version detection (-sV) nmap names the service from its static port
        table (<service method="table">): a guess, e.g. 9100/tcp is always
        "jetdirect". The label says so ("jetdirect, guessed from port") and
        service_confidence is "guessed". A service nmap probed (method="probed")
        is labelled with its name plus the product, version and extra info read
        from the probe, and service_confidence is "probed".
        """
        service = port.find("service")
        if service is None:
            return {"service": "missing name", "service_confidence": SERVICE_GUESSED}
        name = service.get("name") or "missing name"
        if service.get("method") != SERVICE_PROBED:
            return {
                "service": f"{name}, guessed from port",
                "service_confidence": SERVICE_GUESSED,
            }
        details = " ".join(
            v for v in (service.get("product"), service.get("version")) if v
        )
        # No parentheses in the label: OpenAEV shows a finding as
        # "host:port (service)".
        details = ", ".join(
            value for value in (details, service.get("extrainfo")) if value
        )
        result = {
            "service": f"{name}, {details}" if details else name,
            "service_confidence": SERVICE_PROBED,
        }
        for key in ("product", "version", "extrainfo"):
            if service.get(key):
                result[f"service_{key}"] = service.get(key)
        return result

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
                        **NmapOutputParser.service_details(port),
                        "asset_id": None,
                        "host": None,
                    }
                    if selector_is_asset:
                        port_result["asset_id"] = asset_list[idx]
                        port_result["host"] = host.address.get("addr", "missing IP")
                    elif idx < len(targets):
                        port_result["host"] = targets[idx]

                    ports_scans_results.append(port_result)

        outputs = {"scan_results": ports_scans_results, "ports": ports_results}
        # Raw stdout (the nmap XML report), stored as a single non-finding-compatible
        # entry: it never shows up as a visible Finding, but stays usable as a
        # chaining/event filter, independent of what the structured extraction above
        # found.
        # Best-effort decode: lxml above honors whatever encoding the XML
        # declaration specifies, but this is a non-critical, chaining-only
        # field (isFindingCompatible=False) - a non-UTF-8 declared report
        # degrades gracefully here instead of failing the whole parse.
        raw_stdout = stdout.decode("utf-8", errors="replace").strip()
        if raw_stdout:
            outputs["action_output"] = raw_stdout

        return {
            "message": f"Targets successfully scanned ({len(ports_results)} ports found)",
            "outputs": outputs,
        }
