import ipaddress
from typing import Dict, Optional, Tuple


class Properties:

    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        """Filter out loopback, unspecified"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return not (
                ip_obj.is_loopback or ip_obj.is_unspecified or ip_obj.is_link_local
            )
        except ValueError:
            return False

    @staticmethod
    def extract_property_target_value(asset: Dict) -> Optional[Tuple[str, str]]:
        """
        Extract target value from asset based on conditions:
        - Agentless + hostname => hostname
        - Otherwise => first valid IP
        """
        asset_id = asset.get("asset_id")
        agents = asset.get("asset_agents", [])
        hostname = asset.get("endpoint_hostname")
        endpoint_ips = asset.get("endpoint_ips", [])

        # Case 1: Agentless + hostname
        if not agents and hostname:
            return hostname, asset_id

        # Case 2: Agent present => try IPs
        for ip in endpoint_ips:
            if Properties.is_valid_ip(ip):
                return ip, asset_id

        return None
