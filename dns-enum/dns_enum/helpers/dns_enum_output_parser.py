import json
from typing import Dict, Iterable, List

from dns_enum.contracts.dns_enum_constants import (
    ACTION_OUTPUT_FIELD,
    DISCOVERED_HOSTS_FIELD,
    HOSTNAMES_FIELD,
    IPV4_FIELD,
    MANUAL_TARGETS_FIELD,
    RECORD_TYPES,
)

# Keys of a dnsx JSON line holding addresses (the rest are other record values).
_ADDRESS_KEYS = ("a", "aaaa")


def _clean(value: str) -> str:
    return str(value).strip().rstrip(".").lower()


def _merge(target: List[str], values: Iterable[str]) -> None:
    for value in values:
        if value and value not in target:
            target.append(value)


class DnsEnumOutputParser:
    @staticmethod
    def parse_hosts(dnsx_stdout: str, domains: List[str]) -> List[Dict]:
        """Parse dnsx JSON lines into one entry per hostname, deduplicated.

        Each entry: {"host", "ips" (A then AAAA), "records": {type: [values]}}.
        A line with no answer for any requested record type is dropped, as is a
        host outside the requested root domains (a CNAME chain never adds hosts).
        Hosts come back sorted, so a rerun produces the same output.
        """
        hosts: Dict[str, Dict] = {}
        for line in (dnsx_stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(entry, dict):
                continue
            host = _clean(entry.get("host", ""))
            if not host or not DnsEnumOutputParser.in_scope(host, domains):
                continue
            records: Dict[str, List[str]] = {}
            for record_type in RECORD_TYPES:
                values = entry.get(record_type.lower()) or []
                if isinstance(values, str):
                    values = [values]
                cleaned = [_clean(v) for v in values if str(v).strip()]
                if record_type == "TXT":
                    cleaned = [str(v).strip() for v in values if str(v).strip()]
                if cleaned:
                    records[record_type] = cleaned
            if not records:
                continue
            current = hosts.setdefault(host, {"host": host, "ips": [], "records": {}})
            for record_type, values in records.items():
                _merge(current["records"].setdefault(record_type, []), values)
            for key in _ADDRESS_KEYS:
                _merge(current["ips"], current["records"].get(key.upper(), []))
        return [hosts[name] for name in sorted(hosts)]

    @staticmethod
    def in_scope(host: str, domains: List[str]) -> bool:
        return any(host == domain or host.endswith("." + domain) for domain in domains)

    @staticmethod
    def describe(host: Dict) -> str:
        """The finding value of a host: 'host | A: ip, ip | CNAME: target'."""
        parts = [host["host"]]
        for record_type in RECORD_TYPES:
            values = host["records"].get(record_type)
            if values:
                parts.append(f"{record_type}: {', '.join(values)}")
        return " | ".join(parts)

    @staticmethod
    def build_outputs(hosts: List[Dict], raw_output: str) -> Dict:
        ipv4: List[str] = []
        for host in hosts:
            _merge(ipv4, host["records"].get("A", []))
        hostnames = [host["host"] for host in hosts]
        outputs: Dict = {
            DISCOVERED_HOSTS_FIELD: [DnsEnumOutputParser.describe(h) for h in hosts],
            IPV4_FIELD: ipv4,
            HOSTNAMES_FIELD: hostnames,
            MANUAL_TARGETS_FIELD: ",".join(hostnames),
        }
        raw = (raw_output or "").strip()
        if raw:
            outputs[ACTION_OUTPUT_FIELD] = raw
        return outputs
