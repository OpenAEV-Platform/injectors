import ipaddress
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Tuple


@dataclass
class TargetExtractionResult:
    targets: List[str]
    ip_to_asset_id_map: Dict[str, str]


class TargetProperty(Enum):
    AUTOMATIC = "Automatic"
    HOSTNAME = "Hostname"
    SEEN_IP = "Seen IP"
    LOCAL_IP = "Local IP (first)"


target_property_choices_dict = {
    property.name.lower(): property.value for property in TargetProperty
}

class Targets:

    @staticmethod
    def extract_targets(
            data: Dict, helper: OpenAEVInjectorHelper
    ) -> TargetExtractionResult:
        targets = []
        ip_to_asset_id_map = {}
        content = data["injection"]["inject_content"]
        if content[TARGET_SELECTOR_KEY] == "assets" and data.get(ASSETS_KEY):
            selector = content[TARGET_PROPERTY_SELECTOR_KEY]
            for asset in data[ASSETS_KEY]:
                if selector == "automatic":
                    result = Targets.extract_property_target_value(asset)
                    if result:
                        target, asset_id = result
                        targets.append(target)
                        ip_to_asset_id_map[target] = asset_id
                    else:
                        helper.injector_logger.warning(
                            f"No valid target found for asset_id={asset.get('asset_id')} "
                            f"(hostname={asset.get('endpoint_hostname')}, ips={asset.get('endpoint_ips')})"
                        )
                else:
                    if selector == "seen_ip":
                        ip_to_asset_id_map[asset["endpoint_seen_ip"]] = asset[
                            "asset_id"
                        ]
                        targets.append(asset["endpoint_seen_ip"])
                    elif selector == "local_ip":
                        if not asset["endpoint_ips"]:
                            raise ValueError("No IP found for this endpoint")
                        ip_to_asset_id_map[asset["endpoint_ips"][0]] = asset["asset_id"]
                        targets.append(asset["endpoint_ips"][0])
                    else:
                        ip_to_asset_id_map[asset["endpoint_hostname"]] = asset[
                            "asset_id"
                        ]
                        targets.append(asset["endpoint_hostname"])

        elif content[TARGET_SELECTOR_KEY] == "manual":
            targets = [t.strip() for t in content[TARGETS_KEY].split(",") if t.strip()]

        else:
            raise ValueError("No targets provided for this injection")

        return TargetExtractionResult(
            targets=targets, ip_to_asset_id_map=ip_to_asset_id_map
        )

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
