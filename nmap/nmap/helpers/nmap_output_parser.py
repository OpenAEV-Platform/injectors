import re
from typing import Dict, Iterable, List, Optional, Set

from lxml import objectify

from injector_common.targets import (
    MissedTarget,
    TargetExtractionResult,
    TargetResolution,
    Targets,
)

# nmap writes one line per target it cannot resolve on stderr, e.g.
#   Failed to resolve "does-not-exist.invalid".
# and emits no <host> element for it, with exit code 0.
_FAILED_TO_RESOLVE = re.compile(r'Failed to resolve "([^"]+)"')

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
    def unresolved_targets(stderr: Optional[bytes]) -> List[str]:
        """Targets nmap reported it could not resolve, read from its stderr."""
        if not stderr:
            return []
        text = stderr.decode("utf-8", errors="replace")
        return _FAILED_TO_RESOLVE.findall(text)

    @staticmethod
    def _host_values(host) -> Set[str]:
        """Every value a target may have been given as for this host: its addresses
        and its hostnames (the name given on the command line has type 'user')."""
        values: Set[str] = set()
        for address in host.iterchildren(tag="address"):
            if address.get("addr"):
                values.add(address.get("addr").lower())
        hostnames = host.find("hostnames")
        if hostnames is not None:
            for hostname in hostnames.iterchildren(tag="hostname"):
                if hostname.get("name"):
                    values.add(hostname.get("name").lower())
        return values

    @staticmethod
    def _matching_resolutions(
        values: Set[str], resolutions: Iterable[TargetResolution]
    ) -> List[TargetResolution]:
        return [r for r in resolutions if r.target and r.target.lower() in values]

    @staticmethod
    def xmlparse(
        stdout: bytes,
        selector_key: str,
        target_results: TargetExtractionResult,
        stderr: Optional[bytes] = None,
    ) -> dict:
        """Parse XML formatted nmap outputs and extract open ports.

        Each <host> is attributed to the target(s) whose value is one of its addresses
        or hostnames, never by position: a target nmap emitted no <host> for (an
        unresolved hostname) must not shift the ports of the following hosts onto the
        wrong asset. A host matching no target keeps asset_id None. The targets with no
        <host> are returned under "missed".
        """
        xml_parser = objectify.makeparser(resolve_entities=False)
        xml_tree = objectify.fromstring(stdout, xml_parser)

        if xml_tree.tag != "nmaprun":
            raise ValueError("provided stdout does not match expected nmap XML output")

        selector_is_asset = selector_key in ["assets", "asset-groups"]
        resolutions = Targets.resolutions_of(target_results)

        ports_scans_results = []
        ports_results = []
        reached_values: Set[str] = set()

        for host in xml_tree.iterchildren(tag="host"):
            values = NmapOutputParser._host_values(host)
            reached_values |= values
            matches = NmapOutputParser._matching_resolutions(values, resolutions)
            address = host.address.get("addr", "missing IP")

            ports = host.find("ports")
            if ports is None:
                continue
            for port in ports.iterchildren(tag="port"):
                if port.state.get("state") != "open":
                    continue
                portid = int(port.get("portid"))
                ports_results.append(portid)
                service_details = NmapOutputParser.service_details(port)

                if selector_is_asset:
                    owners = [m for m in matches if m.asset_id] or [None]
                    for owner in owners:
                        ports_scans_results.append(
                            {
                                "port": portid,
                                **service_details,
                                "asset_id": owner.asset_id if owner else None,
                                "host": address,
                            }
                        )
                else:
                    ports_scans_results.append(
                        {
                            "port": portid,
                            **service_details,
                            "asset_id": None,
                            "host": matches[0].target if matches else None,
                        }
                    )

        missed: List[MissedTarget] = Targets.missed_targets(
            target_results,
            reached_values,
            NmapOutputParser.unresolved_targets(stderr),
        )

        outputs: Dict = {"scan_results": ports_scans_results, "ports": ports_results}
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

        message = f"Targets successfully scanned ({len(ports_results)} ports found)"
        if missed:
            message = (
                f"Targets partially scanned ({len(ports_results)} ports found, "
                f"{len(missed)} target(s) not scanned)\n"
                + "\n".join(f"- {m.describe()}" for m in missed)
            )

        return {
            "message": message,
            "outputs": outputs,
            "missed": missed,
        }
