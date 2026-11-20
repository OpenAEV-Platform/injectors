import re
from typing import Dict, Iterable, List, Optional, Set

from lxml import objectify

from injector_common.outcomes import (
    HOST_DOWN,
    HOST_UP,
    NOT_SCANNED,
    TargetOutcome,
    build_global_message,
    summarize_outcomes,
)
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

# Port states that prove the host answered (with -Pn every host is reported "up" with
# reason "user-set", so the status alone does not say it responded).
_ANSWERED_PORT_STATES = {"open", "closed", "unfiltered"}

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
    def _host_answered(host) -> bool:
        """Whether the host responded: a status up from a real probe, or at least one
        port (or the extraports summary) in a state only a reply can produce."""
        status = host.find("status")
        if status is not None:
            if status.get("state") == "down":
                return False
            if status.get("state") == "up" and status.get("reason") not in (
                None,
                "user-set",
            ):
                return True
        ports = host.find("ports")
        if ports is None:
            # No port table and no real probe: nothing proves an answer, unless the
            # report carries no reason at all (older or hand-built reports).
            return status is not None and status.get("reason") is None
        for extra in ports.iterchildren(tag="extraports"):
            if extra.get("state") in _ANSWERED_PORT_STATES:
                return True
        for port in ports.iterchildren(tag="port"):
            state = port.find("state")
            if state is not None and state.get("state") in _ANSWERED_PORT_STATES:
                return True
        return status is not None and status.get("reason") is None

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
        exit_code: int = 0,
    ) -> dict:
        """Parse XML formatted nmap outputs and extract open ports.

        Each <host> is attributed to the target(s) whose value is one of its addresses
        or hostnames, never by position: a target nmap emitted no <host> for (an
        unresolved hostname) must not shift the ports of the following hosts onto the
        wrong asset. A host matching no target keeps asset_id None. The targets with no
        <host> are returned under "missed".

        Each target also gets an outcome (host up with its open ports, host down or
        no response, not scanned) under "outcomes", and the global "status" is
        EXECUTED when every target answered, WARNING otherwise or when nmap exited
        with a non-zero ``exit_code`` but its report kept at least one scanned target,
        ERROR when nmap exited non-zero and no target was scanned. On a non-zero
        ``exit_code`` the message ends with nmap's stderr.
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
        # Per target value: whether a host for it answered, and its open ports.
        answered: Dict[str, bool] = {}
        open_ports_by_value: Dict[str, int] = {}

        for host in xml_tree.iterchildren(tag="host"):
            values = NmapOutputParser._host_values(host)
            reached_values |= values
            matches = NmapOutputParser._matching_resolutions(values, resolutions)
            address_node = host.find("address")
            address = (
                address_node.get("addr", "missing IP")
                if address_node is not None
                else "missing IP"
            )
            host_answered = NmapOutputParser._host_answered(host)
            host_open_ports = 0

            ports = host.find("ports")
            port_nodes = [] if ports is None else ports.iterchildren(tag="port")
            for port in port_nodes:
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                portid = int(port.get("portid"))
                ports_results.append(portid)
                host_open_ports += 1
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

            for value in values:
                answered[value] = answered.get(value, False) or host_answered
                open_ports_by_value[value] = (
                    open_ports_by_value.get(value, 0) + host_open_ports
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

        outcomes = NmapOutputParser._outcomes(
            resolutions, missed, answered, open_ports_by_value
        )
        summary = summarize_outcomes(
            outcomes,
            len(ports_results),
            exit_code=exit_code,
            tool="nmap",
            stderr=stderr,
        )

        return {
            "message": build_global_message(summary, outcomes),
            "outputs": outputs,
            "missed": missed,
            "outcomes": outcomes,
            "status": summary.status,
            "exit_code": exit_code,
        }

    @staticmethod
    def _outcomes(
        resolutions: List[TargetResolution],
        missed: List[MissedTarget],
        answered: Dict[str, bool],
        open_ports_by_value: Dict[str, int],
    ) -> List[TargetOutcome]:
        """One outcome per target, in the order the targets were resolved."""
        missed_by_value = {m.resolution.target.lower(): m for m in missed}
        outcomes: List[TargetOutcome] = []
        for resolution in resolutions:
            value = resolution.target.lower()
            miss = missed_by_value.get(value)
            if miss is not None:
                outcomes.append(
                    TargetOutcome(resolution, NOT_SCANNED, reason=miss.reason)
                )
                continue
            if answered.get(value):
                open_ports = open_ports_by_value.get(value, 0)
                outcomes.append(
                    TargetOutcome(resolution, HOST_UP, open_ports=open_ports)
                )
            else:
                outcomes.append(TargetOutcome(resolution, HOST_DOWN))
        return outcomes
