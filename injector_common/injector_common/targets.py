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


@dataclass
class TargetExtractionResult:
    targets: List[str]
    ip_to_asset_id_map: Dict[str, str]


@dataclass
class TargetMeta:
    agent_id: str | None = None
    asset_id: str | None = None


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
    def _build_target_meta(asset: Dict) -> TargetMeta:
        meta = {}
        if asset_id := asset.get("asset_id"):
            meta["asset_id"] = asset_id
        if asset_agents := asset.get("asset_agents"):
            agents_id = list(
                set(
                    agent["agent_id"] for agent in asset_agents if agent.get("agent_id")
                )
            )
            if agents_id:
                meta["agent_id"] = agents_id[0]
        return TargetMeta(**meta)

    @staticmethod
    def extract_target_meta(
        selector_key: str,
        selector_property: str,
        data: dict,
        helper: OpenAEVInjectorHelper,
    ) -> list[TargetMeta]:
        """Return 1+ TargetMeta providing the matching between 1+ asset ID and 0+ agent ID.

        Built from the same assets as extract_targets, an asset without a target value for the
        selector property being skipped as it is there, so that both lists pair by position with
        the execution signatures. An asset gets a single TargetMeta.
        """
        targets: list[TargetMeta] = []

        if (selector_key == "asset-groups" or selector_key == "assets") and data[
            ASSETS_KEY_RABBITMQ
        ]:
            for asset in data[ASSETS_KEY_RABBITMQ]:
                try:
                    target_pair = Targets._get_target(asset, selector_property)
                except Exception as e:
                    helper.injector_logger.error(
                        f"Error processing asset_id={asset.get('asset_id')}: {e}"
                    )
                    continue
                if target_pair is None:
                    continue
                targets.append(Targets._build_target_meta(asset))
            return targets

        if selector_key == "manual":
            helper.injector_logger.info(
                "target meta extraction unsupported for manual inputs, reason: lack of ID"
            )
            return []

        raise ValueError("No targets provided for this injection")

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

        if (selector_key == "asset-groups" or selector_key == "assets") and data[
            ASSETS_KEY_RABBITMQ
        ]:
            assets = data[ASSETS_KEY_RABBITMQ]
            Targets._process_targets(
                assets, selector_property, helper, targets, ip_to_asset_id_map
            )

        elif selector_key == "manual":
            targets = list(
                dict.fromkeys(
                    [t.strip() for t in content[TARGETS_KEY].split(",") if t.strip()]
                )
            )

        else:
            raise ValueError("No targets provided for this injection")

        return TargetExtractionResult(
            targets=targets, ip_to_asset_id_map=ip_to_asset_id_map
        )

    @staticmethod
    def _process_targets(
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
                target_pair = Targets._get_target(asset, selector)
                if target_pair:
                    target, asset_id = target_pair
                    targets.append(target)
                    ip_to_asset_id_map[target] = asset_id
                else:
                    helper.injector_logger.warning(
                        f"No valid target found for asset_id={asset.get('asset_id')} "
                        f"(hostname={asset.get('asset_hostname')}, ips={asset.get('asset_ips')})"
                    )

            except Exception as e:
                helper.injector_logger.error(
                    f"Error processing asset_id={asset.get('asset_id')}: {e}"
                )

    @staticmethod
    def _get_target(asset: Dict, selector: str) -> Optional[Tuple[str, str]]:
        """Return (target_value, asset_id) or None if not available."""
        asset_id = asset.get("asset_id")

        if selector == "automatic":
            result = Targets._extract_property_target_value(asset)
            if result:
                return result

        elif selector == "seen_ip":
            seen_ip = asset.get("asset_seen_ip")
            if Targets._is_valid_ip(seen_ip):
                return seen_ip, asset_id
            else:
                return None

        elif selector == "local_ip":
            asset_ips = asset.get("asset_ips") or []
            # Validate each IP
            for ip in asset_ips:
                if Targets._is_valid_ip(ip):
                    return ip, asset_id
            # No valid IPs found
            return None

        elif selector == "hostname":
            hostname = asset.get("asset_hostname")
            if hostname:
                return hostname, asset_id

        # Nothing valid found
        return None

    @staticmethod
    def _is_valid_ip(ip: Optional[str]) -> bool:
        """Filter out loopback, unspecified ip.

        Accepts an optional value because callers pass raw payload fields
        (asset_seen_ip is optional and may be missing or None). A None or
        non-string value is treated as invalid: ipaddress.ip_address raises
        ValueError for None/empty strings and TypeError for other types.
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            return not (
                ip_obj.is_loopback or ip_obj.is_unspecified or ip_obj.is_link_local
            )
        except (ValueError, TypeError):
            return False

    @staticmethod
    def _extract_property_target_value(asset: Dict) -> Optional[Tuple[str, str]]:
        """
        Extract target value from asset based on conditions:
        - Agentless + hostname => hostname
        - Otherwise => seen IP, else first valid local IP

        The seen IP comes before the local ones because it is the address the platform
        actually observed the endpoint at, and it is what the endpoint screen displays.
        Going straight to the local IPs made the execution target an address the UI never
        showed - an endpoint listed as 74.234.220.121 scanned at 192.168.56.11.
        """
        asset_id = asset.get("asset_id")
        agents = asset.get("asset_agents", [])
        hostname = asset.get("asset_hostname")
        asset_ips = asset.get("asset_ips", [])

        # Case 1: Agentless + hostname
        if not agents and hostname:
            return hostname, asset_id

        # Case 2: the address the platform saw this endpoint at
        seen_ip = asset.get("asset_seen_ip")
        if Targets._is_valid_ip(seen_ip):
            return seen_ip, asset_id

        # Case 3: no usable seen IP => fall back to the local ones
        for ip in asset_ips:
            if Targets._is_valid_ip(ip):
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
