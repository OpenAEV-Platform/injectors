import ipaddress
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Tuple

from pyoaev.helpers import OpenAEVInjectorHelper

from injector_common.constants import (
    ASSET_GROUPS_KEY_RABBITMQ,
    ASSETS_KEY_RABBITMQ,
    TARGETS_KEY,
)
from injector_common.pagination import Pagination


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
        selector_key: str,
        selector_property: str,
        data: Dict,
        helper: OpenAEVInjectorHelper,
    ) -> TargetExtractionResult:
        """Return TargetExtractionResults built from target id and target property."""
        targets: List[str] = []
        ip_to_asset_id_map: Dict[str, str] = {}
        content = data["injection"]["inject_content"]

        if selector_key == "asset-groups" and data[ASSET_GROUPS_KEY_RABBITMQ]:
            helper.injector_logger.info(
                "Fetching all endpoint targets from asset groups with pagination"
            )
            asset_group_ids = [
                g["asset_group_id"] for g in data[ASSET_GROUPS_KEY_RABBITMQ]
            ]
            assets = Pagination.fetch_all_targets(helper, asset_group_ids)
            helper.injector_logger.info(f"Fetched {len(assets)} assets from groups.")
            Targets.process_targets(
                assets, selector_property, helper, targets, ip_to_asset_id_map
            )

        elif selector_key == "assets" and data[ASSETS_KEY_RABBITMQ]:
            assets = data[ASSETS_KEY_RABBITMQ]
            Targets.process_targets(
                assets, selector_property, helper, targets, ip_to_asset_id_map
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
        helper: "OpenAEVInjectorHelper",
        targets: List[str],
        ip_to_asset_id_map: Dict[str, str],
    ) -> None:
        """Extract property based on TARGET_PROPERTY."""
        # Process all assets
        for asset in assets:
            try:
                target_pair = Targets.get_target(asset, selector)
                if target_pair:
                    target, asset_id = target_pair
                    targets.append(target)
                    ip_to_asset_id_map[target] = asset_id
                else:
                    helper.injector_logger.warning(
                        f"No valid target found for asset_id={asset.get('asset_id')} "
                        f"(hostname={asset.get('endpoint_hostname')}, ips={asset.get('endpoint_ips')})"
                    )

            except Exception as e:
                helper.injector_logger.error(
                    f"Error processing asset_id={asset.get('asset_id')}: {e}"
                )

    @staticmethod
    def get_target(asset: Dict, selector: str) -> Optional[Tuple[str, str]]:
        """Return (target_value, asset_id) or None if not available."""
        asset_id = asset.get("asset_id")

        if selector == "automatic":
            result = Targets.extract_property_target_value(asset)
            if result:
                return result

        elif selector == "seen_ip":
            seen_ip = asset.get("endpoint_seen_ip")
            if Targets.is_valid_ip(seen_ip):
                return seen_ip, asset_id
            else:
                return None

        elif selector == "local_ip":
            endpoint_ips = asset.get("endpoint_ips") or []
            # Validate each IP
            for ip in endpoint_ips:
                if Targets.is_valid_ip(ip):
                    return ip, asset_id
            # No valid IPs found
            return None

        elif selector == "hostname":
            hostname = asset.get("endpoint_hostname")
            if hostname:
                return hostname, asset_id

        # Nothing valid found
        return None

    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        """Filter out loopback, unspecified ip"""
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

    @staticmethod
    def build_execution_message(
        selector_key: str, data: Dict, command_args: List[str]
    ) -> str:
        """
        Return the execution message depending on selector_key.
        - For 'asset-groups': returns a comma-separated list of asset group names.
        - For others ('assets', 'manual', etc.): returns the command arguments joined as a string.
        """
        if selector_key == "asset-groups":
            asset_group_names = [
                g["asset_group_name"]
                for g in data[ASSET_GROUPS_KEY_RABBITMQ]
                if g["asset_group_name"]
            ]
            group_str = ", ".join(asset_group_names)
            command_str = " ".join(command_args)
            return f"The inject was executed in {group_str} with command {command_str}"
        else:
            return " ".join(command_args)
