import ipaddress
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Tuple

from pyoaev.helpers import OpenAEVInjectorHelper

from common.constants import (
    ASSET_GROUPS_KEY,
    ASSETS_KEY,
    TARGET_PROPERTY_SELECTOR_KEY,
    TARGET_SELECTOR_KEY,
    TARGETS_KEY,
)
from common.pagination import Pagination


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
        targets: List[str] = []
        ip_to_asset_id_map: Dict[str, str] = {}
        content = data["injection"]["inject_content"]

        selector_key = content[TARGET_SELECTOR_KEY]
        selector = content.get(TARGET_PROPERTY_SELECTOR_KEY)

        if selector_key == "asset-groups" and data.get(ASSET_GROUPS_KEY):
            helper.injector_logger.info(
                "Fetching all targets from asset groups with pagination..."
            )
            asset_group_ids = [g["asset_group_id"] for g in data[ASSET_GROUPS_KEY]]
            assets = Pagination.fetch_all_targets(helper,asset_group_ids)
            helper.injector_logger.info(f"Fetched {len(assets)} assets from groups.")

            Targets.process_targets(
                assets, selector, helper, targets, ip_to_asset_id_map
            )

        elif selector_key == "assets" and data.get(ASSETS_KEY):
            assets = data[ASSETS_KEY]
            Targets.process_targets(
                assets, selector, helper, targets, ip_to_asset_id_map
            )

        elif selector_key == "manual":
            targets = [t.strip() for t in content[TARGETS_KEY].split(",") if t.strip()]

        else:
            raise ValueError("No targets provided for this injection")

        return TargetExtractionResult(
            targets=targets, ip_to_asset_id_map=ip_to_asset_id_map
        )

    @staticmethod
    def process_targets(
            assets: List[Dict],
            selector: str,
            helper: OpenAEVInjectorHelper,
            targets: List[str],
            ip_to_asset_id_map: Dict[str, str],
    ) -> None:
        """Shared logic for processing asset-based targets."""
        for asset in assets:
            try:
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

                elif selector == "seen_ip":
                    ip_to_asset_id_map[asset["endpoint_seen_ip"]] = asset["asset_id"]
                    targets.append(asset["endpoint_seen_ip"])

                elif selector == "local_ip":
                    ips = asset.get("endpoint_ips", [])
                    if not ips:
                        raise ValueError(
                            f"No IPs found for endpoint {asset.get('asset_id')}"
                        )
                    ip_to_asset_id_map[ips[0]] = asset["asset_id"]
                    targets.append(ips[0])

                else:  # hostname
                    ip_to_asset_id_map[asset["endpoint_hostname"]] = asset["asset_id"]
                    targets.append(asset["endpoint_hostname"])

            except Exception as e:
                helper.injector_logger.error(
                    f"Error processing asset_id={asset.get('asset_id')}: {e}"
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
            if Targets.is_valid_ip(ip):
                return ip, asset_id

        return None
