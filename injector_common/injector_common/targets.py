import ipaddress
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Iterable, List, Optional, Tuple

from pyoaev.helpers import OpenAEVInjectorHelper

from injector_common.constants import (
    ASSET_GROUPS_KEY_RABBITMQ,
    ASSETS_KEY_RABBITMQ,
    TARGETS_KEY,
)


# Human-readable name of each asset field a target value can come from.
TARGET_VALUE_LABELS = {
    "hostname": "hostname",
    "seen_ip": "seen IP",
    "local_ip": "local IP",
    "manual": "manual target",
}

NOT_RESOLVED_REASON = "hostname did not resolve"
NO_RESULT_REASON = "no result returned by the scan"


@dataclass
class TargetResolution:
    """How one target value was chosen: the asset it stands for and the field it came from.

    ``value_property`` is the asset field actually used (hostname, seen_ip, local_ip, or
    manual), ``selector`` the target property requested on the inject (automatic,
    hostname, seen_ip, local_ip, or manual). Under ``automatic`` both differ, which is
    exactly what a user needs to see to understand why an asset was scanned at a value.
    """

    target: str
    asset_id: Optional[str] = None
    asset_name: Optional[str] = None
    value_property: Optional[str] = None
    selector: Optional[str] = None
    agentless: bool = False

    def asset_label(self) -> Optional[str]:
        return self.asset_name or self.asset_id

    def describe(self) -> str:
        """E.g. 'asset web-01: hostname web-01.example.com (automatic, agentless)'."""
        label = TARGET_VALUE_LABELS.get(self.value_property or "", "target")
        text = f"{label} {self.target}"
        if self.selector:
            qualifiers = [self.selector]
            if (
                self.selector == "automatic"
                and self.agentless
                and self.value_property == "hostname"
            ):
                qualifiers.append("agentless")
            text += f" ({', '.join(qualifiers)})"
        if self.asset_label():
            return f"asset {self.asset_label()}: {text}"
        return text


@dataclass
class MissedTarget:
    """A target the tool was asked to reach and returned nothing for."""

    resolution: TargetResolution
    reason: str

    def describe(self) -> str:
        target = self.resolution.target
        if self.resolution.asset_label():
            return (
                f"{target} (asset {self.resolution.asset_label()}): not scanned, "
                f"{self.reason}"
            )
        return f"{target}: not scanned, {self.reason}"


@dataclass
class TargetExtractionResult:
    targets: List[str]
    ip_to_asset_id_map: Dict[str, str]
    # One entry per resolved asset, duplicates included (the map above collapses two
    # assets resolving to the same value into one key).
    resolutions: List[TargetResolution] = field(default_factory=list)


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
        resolutions: List[TargetResolution] = []
        content = data["injection"]["inject_content"]

        if (selector_key == "asset-groups" or selector_key == "assets") and data[
            ASSETS_KEY_RABBITMQ
        ]:
            assets = data[ASSETS_KEY_RABBITMQ]
            Targets._process_targets(
                assets,
                selector_property,
                helper,
                targets,
                ip_to_asset_id_map,
                resolutions,
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
            targets=targets,
            ip_to_asset_id_map=ip_to_asset_id_map,
            resolutions=resolutions,
        )

    @staticmethod
    def _process_targets(
        assets: List[Dict],
        selector: str,
        helper: "OpenAEVInjectorHelper",
        targets: List[str],
        ip_to_asset_id_map: Dict[str, str],
        resolutions: Optional[List[TargetResolution]] = None,
    ) -> None:
        """Extract property based on TARGET_PROPERTY."""
        # Process all assets
        for asset in assets:
            try:
                resolution = Targets._resolve_target(asset, selector)
                if resolution:
                    targets.append(resolution.target)
                    ip_to_asset_id_map[resolution.target] = resolution.asset_id
                    if resolutions is not None:
                        resolutions.append(resolution)
                    helper.injector_logger.info(
                        f"Target resolved: {resolution.describe()}"
                    )
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
        resolution = Targets._resolve_target(asset, selector)
        if resolution is None:
            return None
        return resolution.target, resolution.asset_id

    @staticmethod
    def _resolve_target(asset: Dict, selector: str) -> Optional[TargetResolution]:
        """Return the target value of an asset with the field it came from, or None."""
        asset_id = asset.get("asset_id")
        asset_name = asset.get("asset_name")

        def resolved(value: str, value_property: str) -> TargetResolution:
            return TargetResolution(
                target=value,
                asset_id=asset_id,
                asset_name=asset_name,
                value_property=value_property,
                selector=selector,
                agentless=not asset.get("asset_agents"),
            )

        if selector == "automatic":
            choice = Targets._extract_property_target_choice(asset)
            if choice:
                return resolved(*choice)

        elif selector == "seen_ip":
            seen_ip = asset.get("asset_seen_ip")
            if Targets._is_valid_ip(seen_ip):
                return resolved(seen_ip, "seen_ip")
            return None

        elif selector == "local_ip":
            ip = Targets._first_valid_ip(asset.get("asset_ips") or [])
            if ip:
                return resolved(ip, "local_ip")
            return None

        elif selector == "hostname":
            hostname = asset.get("asset_hostname")
            if hostname:
                return resolved(hostname, "hostname")

        # Nothing valid found
        return None

    @staticmethod
    def _first_valid_ip(ips: Iterable[Optional[str]]) -> Optional[str]:
        for ip in ips:
            if Targets._is_valid_ip(ip):
                return ip
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
        choice = Targets._extract_property_target_choice(asset)
        if choice is None:
            return None
        return choice[0], asset.get("asset_id")

    @staticmethod
    def _extract_property_target_choice(asset: Dict) -> Optional[Tuple[str, str]]:
        """Return (target_value, asset field used) for the automatic property, in order:
        agentless with a hostname -> hostname; else a valid seen IP; else the first valid
        local IP; else None (the asset is skipped)."""
        agents = asset.get("asset_agents", [])
        hostname = asset.get("asset_hostname")

        # Case 1: Agentless + hostname
        if not agents and hostname:
            return hostname, "hostname"

        # Case 2: the address the platform saw this endpoint at
        seen_ip = asset.get("asset_seen_ip")
        if Targets._is_valid_ip(seen_ip):
            return seen_ip, "seen_ip"

        # Case 3: no usable seen IP => fall back to the local ones
        ip = Targets._first_valid_ip(asset.get("asset_ips") or [])
        if ip:
            return ip, "local_ip"

        return None

    @staticmethod
    def resolutions_of(
        target_results: TargetExtractionResult,
    ) -> List[TargetResolution]:
        """Every target with its asset, also for results built without resolutions
        (manual targets, or callers building TargetExtractionResult by hand)."""
        if target_results.resolutions:
            return list(target_results.resolutions)
        resolutions = [
            TargetResolution(target=target, asset_id=asset_id)
            for target, asset_id in (target_results.ip_to_asset_id_map or {}).items()
        ]
        known = {r.target for r in resolutions}
        for target in target_results.targets or []:
            if target not in known:
                known.add(target)
                resolutions.append(
                    TargetResolution(target=target, value_property="manual")
                )
        return resolutions

    @staticmethod
    def missed_targets(
        target_results: TargetExtractionResult,
        reached_values: Iterable[str],
        unresolved_values: Iterable[str] = (),
    ) -> List[MissedTarget]:
        """Targets the tool returned nothing for, matched by value, never by position.

        ``reached_values`` are the addresses and hostnames the tool reported results
        for; ``unresolved_values`` the targets it said it could not resolve. Comparison
        ignores case (DNS names are case-insensitive).
        """
        reached = {v.lower() for v in reached_values if v}
        unresolved = {v.lower() for v in unresolved_values if v}
        missed: List[MissedTarget] = []
        for resolution in Targets.resolutions_of(target_results):
            value = resolution.target.lower()
            if value in unresolved:
                missed.append(MissedTarget(resolution, NOT_RESOLVED_REASON))
            elif value not in reached:
                reason = (
                    NO_RESULT_REASON
                    if Targets._is_ip(resolution.target)
                    else NOT_RESOLVED_REASON
                )
                missed.append(MissedTarget(resolution, reason))
        return missed

    @staticmethod
    def _is_ip(value: Optional[str]) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except (ValueError, TypeError):
            return False

    @staticmethod
    def build_execution_message(
        selector_key: str,
        data: Dict,
        command_args: List[str],
        target_results: Optional[TargetExtractionResult] = None,
    ) -> str:
        """
        Return the execution message depending on selector_key.
        - For 'asset-groups': returns a comma-separated list of asset group names.
        - For others ('assets', 'manual', etc.): returns the command arguments joined as a string.
        When target_results is given and targets were resolved with the 'automatic'
        property, one line per asset names the field used and its value, so the user
        sees why an asset was reached at a given hostname or address.
        """
        if selector_key == "asset-groups":
            asset_group_names = [
                g["asset_group_name"]
                for g in data[ASSET_GROUPS_KEY_RABBITMQ]
                if g["asset_group_name"]
            ]
            group_str = ", ".join(asset_group_names)
            command_str = " ".join(command_args)
            message = (
                f"The inject was executed in {group_str} with command {command_str}"
            )
        else:
            message = " ".join(command_args)
        return message + Targets.describe_resolutions(target_results)

    @staticmethod
    def describe_resolutions(
        target_results: Optional[TargetExtractionResult],
    ) -> str:
        """'\\nResolved targets:' followed by one line per automatically resolved asset,
        or an empty string when no target was resolved with the automatic property."""
        if target_results is None:
            return ""
        lines = [
            f"- {r.describe()}"
            for r in target_results.resolutions
            if r.selector == "automatic"
        ]
        if not lines:
            return ""
        return "\nResolved targets:\n" + "\n".join(lines)
