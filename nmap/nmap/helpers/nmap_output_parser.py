import re
from typing import Dict, Iterable, List, Optional, Set

from lxml import objectify

from injector_common.outcomes import (
    ERROR,
    HOST_DOWN,
    HOST_UP,
    NOT_SCANNED,
    WARNING,
    TargetOutcome,
    build_global_message,
    summarize_outcomes,
)
from injector_common.scan_budget import SCAN_TIMEOUT_FIELD
from injector_common.targets import (
    MissedTarget,
    TargetExtractionResult,
    TargetResolution,
    Targets,
)

# Why a target got no result when nmap was terminated at its scan time limit.
TIME_LIMIT_REASON = "scan time limit reached"
# The report of a run killed before nmap wrote its XML header.
_EMPTY_REPORT = b'<?xml version="1.0"?><nmaprun scanner="nmap"></nmaprun>'

# nmap writes one line per target it cannot resolve on stderr, e.g.
#   Failed to resolve "does-not-exist.invalid".
# and emits no <host> element for it, with exit code 0.
_FAILED_TO_RESOLVE = re.compile(r'Failed to resolve "([^"]+)"')

# Port states that prove the host answered (with -Pn every host is reported "up" with
# reason "user-set", so the status alone does not say it responded).
_ANSWERED_PORT_STATES = {"open", "closed", "unfiltered"}

# ICMP answers nmap names as the reason of a filtered port: something on the path
# replied, so the probes reached it (a firewall rule, not a dropped scan).
_ICMP_REJECT_REASONS = {
    "admin-prohibited",
    "host-prohibited",
    "net-prohibited",
    "host-unreach",
    "net-unreach",
    "port-unreach",
    "proto-unreach",
}

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
    def _silence_reason(host) -> Optional[str]:
        """Why a host that did not answer gave no answer, from the report: a host
        discovery that said down, every scanned port filtered with no reply, or every
        port filtered with an ICMP reject (a firewall that answered). None when the
        report says nothing more."""
        status = host.find("status")
        if status is not None and status.get("state") == "down":
            return "host down (no reply to host discovery)"
        ports = host.find("ports")
        if ports is None:
            return None
        filtered = 0
        reasons: Dict[str, int] = {}
        for extra in ports.iterchildren(tag="extraports"):
            if extra.get("state") not in ("filtered", "open|filtered"):
                continue
            count = int(extra.get("count") or 0)
            filtered += count
            listed = 0
            for extra_reason in extra.iterchildren(tag="extrareasons"):
                n = int(extra_reason.get("count") or 0)
                listed += n
                key = extra_reason.get("reason") or ""
                reasons[key] = reasons.get(key, 0) + n
            if count > listed:
                reasons[""] = reasons.get("", 0) + count - listed
        for port in ports.iterchildren(tag="port"):
            state = port.find("state")
            if state is None or state.get("state") not in ("filtered", "open|filtered"):
                continue
            filtered += 1
            key = state.get("reason") or ""
            reasons[key] = reasons.get(key, 0) + 1
        if not filtered:
            return None
        plural = "port" if filtered == 1 else "ports"
        rejected = {r: n for r, n in reasons.items() if r in _ICMP_REJECT_REASONS}
        if rejected:
            names = ", ".join(sorted(rejected))
            return (
                f"{filtered} {plural} filtered, {sum(rejected.values())} rejected by "
                f"ICMP {names} (a firewall answered)"
            )
        if "no-response" in reasons and set(reasons) <= {"no-response", ""}:
            return (
                f"{filtered} {plural} filtered, no reply (host down or every probe "
                "dropped)"
            )
        return f"{filtered} {plural} filtered"

    @staticmethod
    def _matching_resolutions(
        values: Set[str], resolutions: Iterable[TargetResolution]
    ) -> List[TargetResolution]:
        return [r for r in resolutions if r.target and r.target.lower() in values]

    @staticmethod
    def salvage_partial(stdout: Optional[bytes]) -> bytes:
        """A parseable report out of the output of an nmap run killed at its time
        limit: the completed <host> elements kept, the rest cut, the root closed.

        nmap writes each <host> of its XML report once the host is finished, so
        the output of a killed run is a valid report truncated after some host.
        Output with no <nmaprun> start gives an empty report (no host scanned)."""
        data = stdout or b""
        root = data.find(b"<nmaprun")
        if root < 0 or data.find(b">", root) < 0:
            return _EMPTY_REPORT
        last_host = data.rfind(b"</host>")
        if last_host >= 0:
            end = last_host + len(b"</host>")
        else:
            end = data.find(b">", root) + 1
        return data[:end] + b"</nmaprun>"

    @staticmethod
    def xmlparse(
        stdout: bytes,
        selector_key: str,
        target_results: TargetExtractionResult,
        stderr: Optional[bytes] = None,
        exit_code: int = 0,
        time_limit_seconds: Optional[int] = None,
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

        ``time_limit_seconds`` is set when nmap was terminated at its scan time
        limit (``stdout`` then comes from salvage_partial): a target with no <host>
        is not scanned because the time limit was reached, and the status is
        WARNING when at least one target was scanned, ERROR otherwise.
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
        silence_by_value: Dict[str, str] = {}
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
            silence = None if host_answered else NmapOutputParser._silence_reason(host)
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
                if silence and value not in silence_by_value:
                    silence_by_value[value] = silence
                open_ports_by_value[value] = (
                    open_ports_by_value.get(value, 0) + host_open_ports
                )

        unresolved = NmapOutputParser.unresolved_targets(stderr)
        missed: List[MissedTarget] = Targets.missed_targets(
            target_results, reached_values, unresolved
        )
        if time_limit_seconds:
            # Cut before nmap reached them: a hostname nmap said it could not
            # resolve keeps that reason, every other miss is the time limit.
            unresolved_values = {v.lower() for v in unresolved}
            missed = [
                (
                    m
                    if m.resolution.target.lower() in unresolved_values
                    else MissedTarget(m.resolution, TIME_LIMIT_REASON)
                )
                for m in missed
            ]

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
            resolutions, missed, answered, open_ports_by_value, silence_by_value
        )
        summary = summarize_outcomes(
            outcomes,
            len(ports_results),
            exit_code=exit_code,
            tool="nmap",
            stderr=stderr,
        )

        message = build_global_message(summary, outcomes)
        status = summary.status
        if time_limit_seconds:
            status = WARNING if summary.scanned else ERROR
            message = (
                f"nmap terminated at its {time_limit_seconds} s scan time limit: "
                "results partial, the hosts finished before the limit are kept. "
                f"Raise the limit with the inject field '{SCAN_TIMEOUT_FIELD}' or the "
                "NMAP_SCAN_TIMEOUT key of the injector deployment, or reduce the "
                "scan scope (fewer targets, ports or a faster timing template).\n"
                + message
            )

        return {
            "message": message,
            "outputs": outputs,
            "missed": missed,
            "outcomes": outcomes,
            "status": status,
            "exit_code": exit_code,
        }

    @staticmethod
    def _outcomes(
        resolutions: List[TargetResolution],
        missed: List[MissedTarget],
        answered: Dict[str, bool],
        open_ports_by_value: Dict[str, int],
        silence_by_value: Optional[Dict[str, str]] = None,
    ) -> List[TargetOutcome]:
        """One outcome per target, in the order the targets were resolved. A target
        that gave no answer carries why, when the report says (all ports filtered
        with no reply, or rejected by ICMP)."""
        silence_by_value = silence_by_value or {}
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
                outcomes.append(
                    TargetOutcome(
                        resolution, HOST_DOWN, reason=silence_by_value.get(value)
                    )
                )
        return outcomes
