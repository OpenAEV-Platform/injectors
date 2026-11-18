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


class NmapOutputParser:
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
        with a non-zero ``exit_code`` but its report was kept.
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
                service_node = port.find("service")
                service = (
                    service_node.get("name", "missing name")
                    if service_node is not None
                    else "missing name"
                )

                if selector_is_asset:
                    owners = [m for m in matches if m.asset_id] or [None]
                    for owner in owners:
                        ports_scans_results.append(
                            {
                                "port": portid,
                                "service": service,
                                "asset_id": owner.asset_id if owner else None,
                                "host": address,
                            }
                        )
                else:
                    ports_scans_results.append(
                        {
                            "port": portid,
                            "service": service,
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
            outcomes, len(ports_results), exit_code=exit_code, tool="nmap"
        )

        return {
            "message": build_global_message(summary, outcomes),
            "outputs": outputs,
            "missed": missed,
            "outcomes": outcomes,
            "status": summary.status,
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
