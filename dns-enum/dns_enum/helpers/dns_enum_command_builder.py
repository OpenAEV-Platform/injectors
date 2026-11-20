from typing import List

SUBFINDER_BINARY = "subfinder"
DNSX_BINARY = "dnsx"


class DnsEnumCommandBuilder:
    @staticmethod
    def subfinder_args(domains_file: str, rate_limit: int, timeout: int) -> List[str]:
        """Passive subdomain enumeration of every root domain listed in domains_file."""
        return [
            SUBFINDER_BINARY,
            "-dL",
            domains_file,
            "-silent",
            "-duc",
            "-rl",
            str(rate_limit),
            "-max-time",
            str(max(1, timeout // 60)),
        ]

    @staticmethod
    def dnsx_args(
        hosts_file: str, record_types: List[str], rate_limit: int
    ) -> List[str]:
        """Active resolution of every candidate host, one JSON line per host."""
        args = [DNSX_BINARY, "-l", hosts_file, "-silent", "-json", "-duc"]
        args += ["-" + record_type.lower() for record_type in record_types]
        args += ["-rl", str(rate_limit)]
        return args

    @staticmethod
    def brute_force_candidates(domains: List[str], words: List[str]) -> List[str]:
        """word.domain for every word and every root domain, order kept."""
        return [f"{word}.{domain}" for domain in domains for word in words]
