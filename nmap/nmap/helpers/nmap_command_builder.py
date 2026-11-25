import re
from typing import Dict, List, Optional

from nmap.contracts.nmap_constants import (
    FIN_SCAN_CONTRACT,
    HOST_TIMEOUT_KEY,
    MAX_RETRIES_KEY,
    MAX_RTT_TIMEOUT_KEY,
    MIN_RATE_KEY,
    PORTS_KEY,
    TCP_CONNECT_SCAN_CONTRACT,
    TCP_SYN_SCAN_CONTRACT,
    TCP_SYN_VERSION_SCAN_CONTRACT,
    TIMING_DEFAULT,
    TIMING_KEY,
    TIMING_TEMPLATES,
    TOP_PORTS_KEY,
)

# A port list as nmap takes it: numbers and ranges, optionally prefixed by a protocol
# (T:, U:), comma-separated. Nothing else reaches the command line.
_PORT_SPEC = re.compile(
    r"^(?:[TU]:)?\d{1,5}(?:-\d{1,5})?(?:,(?:[TU]:)?\d{1,5}(?:-\d{1,5})?)*$"
)

# Each tuning option: the nmap flag, the largest accepted value, the unit suffix nmap
# reads for a time (None: a plain count).
_NUMERIC_OPTIONS = {
    MAX_RETRIES_KEY: ("--max-retries", 10, None),
    HOST_TIMEOUT_KEY: ("--host-timeout", 86400, "s"),
    MAX_RTT_TIMEOUT_KEY: ("--max-rtt-timeout", 60000, "ms"),
    MIN_RATE_KEY: ("--min-rate", 100000, None),
    TOP_PORTS_KEY: ("--top-ports", 65535, None),
}


class NmapCommandBuilder:
    @staticmethod
    def _text(options: Optional[Dict], key: str) -> str:
        value = (options or {}).get(key)
        if isinstance(value, list):
            value = value[0] if value else None
        return str(value).strip() if value is not None else ""

    @staticmethod
    def tuning_args(options: Optional[Dict]) -> List[str]:
        """The optional timing, retry and port selection flags of the inject content.

        Every value is validated before it reaches the command line: a template among
        T0 to T5, whole numbers within bounds, a port list of numbers and ranges. An
        invalid value raises ValueError naming the field, so the inject ends with a
        pre-execution failure instead of running a scan the operator did not ask for.
        An empty field adds nothing: nmap's default applies.
        """
        args: List[str] = []
        timing = NmapCommandBuilder._text(options, TIMING_KEY)
        if timing and timing != TIMING_DEFAULT:
            if timing not in TIMING_TEMPLATES:
                raise ValueError(
                    f"Invalid timing template '{timing}': expected one of "
                    + ", ".join(TIMING_TEMPLATES)
                )
            args.append(f"-{timing}")
        for key, (flag, maximum, unit) in _NUMERIC_OPTIONS.items():
            value = NmapCommandBuilder._text(options, key)
            if not value:
                continue
            if not value.isdigit() or not 0 <= int(value) <= maximum:
                raise ValueError(
                    f"Invalid value '{value}' for {flag}: expected a whole number "
                    f"from 0 to {maximum}"
                    + (
                        f" ({'seconds' if unit == 's' else 'milliseconds'})"
                        if unit
                        else ""
                    )
                )
            if key == TOP_PORTS_KEY and int(value) == 0:
                raise ValueError(
                    "Invalid value '0' for --top-ports: expected at least 1"
                )
            args += [flag, f"{int(value)}{unit or ''}"]
        ports = NmapCommandBuilder._text(options, PORTS_KEY).replace(" ", "")
        if ports:
            if NmapCommandBuilder._text(options, TOP_PORTS_KEY):
                raise ValueError(
                    "Set either the ports to scan or the top ports, not both"
                )
            if not _PORT_SPEC.match(ports) or any(
                int(n) > 65535 for n in re.findall(r"\d+", ports)
            ):
                raise ValueError(
                    f"Invalid ports '{ports}': expected numbers and ranges from 1 to "
                    "65535, comma-separated (e.g. 22,80,443,8000-8100)"
                )
            args += ["-p", ports]
        return args

    @staticmethod
    def build_args(
        contract_id: str, targets: List[str], options: Optional[Dict] = None
    ) -> List[str]:
        """Build a list of nmap command-line arguments for a given contract."""
        args = ["nmap", "-Pn"]

        if contract_id == TCP_SYN_SCAN_CONTRACT:
            args.append("-sS")
        elif contract_id == TCP_CONNECT_SCAN_CONTRACT:
            args.append("-sT")
        elif contract_id == FIN_SCAN_CONTRACT:
            args.append("-sF")
        elif contract_id == TCP_SYN_VERSION_SCAN_CONTRACT:
            # Service/version detection: nmap probes each open port instead of
            # naming its service from the static port table.
            args += ["-sS", "-sV"]
        # --reason: the XML report then carries why each port is filtered (no reply,
        # an ICMP unreachable, a reset), which the outcome of a silent host names.
        args += NmapCommandBuilder.tuning_args(options)
        args = args + ["--reason", "-oX", "-"]

        for target in targets:
            args += [target]

        return args
