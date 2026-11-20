from typing import Dict, List, Optional

from dns_enum.contracts.dns_enum_constants import (
    ENDPOINT_TAG_COLOR,
    EXTERNAL_REFERENCE_PREFIX,
)


def external_reference(hostname: str) -> str:
    """Stable reference of a discovered host: the platform's upsert matches on it
    first, so a rerun updates the same endpoint instead of creating a second one."""
    return EXTERNAL_REFERENCE_PREFIX + hostname.strip().rstrip(".").lower()


def build_endpoint_input(host: Dict, tag_id: Optional[str]) -> Dict:
    hostname = host["host"]
    endpoint = {
        "asset_name": hostname,
        "asset_hostname": hostname,
        "asset_external_reference": external_reference(hostname),
        "asset_description": "Discovered by DNS enumeration",
        "asset_internet_facing": True,
    }
    if host.get("ips"):
        endpoint["asset_ips"] = list(host["ips"])
    if tag_id:
        endpoint["asset_tags"] = [tag_id]
    return endpoint


def dedupe_hosts(hosts: List[Dict]) -> List[Dict]:
    """One host per external reference, the first one kept; hosts without any IP
    are skipped (an endpoint is created only for a host that resolves)."""
    seen = set()
    unique: List[Dict] = []
    for host in hosts:
        if not host.get("ips"):
            continue
        reference = external_reference(host["host"])
        if reference in seen:
            continue
        seen.add(reference)
        unique.append(host)
    return unique


class EndpointImporter:
    def __init__(self, api, logger):
        self.api = api
        self.logger = logger

    def _tag_id(self, tag_name: str) -> Optional[str]:
        try:
            tag = self.api.tag.upsert(
                {"tag_name": tag_name, "tag_color": ENDPOINT_TAG_COLOR}
            )
        except Exception as err:  # the import goes on without the tag
            self.logger.error(f"Tag upsert failed for {tag_name!r}: {err}")
            return None
        return (tag or {}).get("tag_id")

    def _add_to_asset_group(self, asset_group_id: str, asset_ids: List[str]) -> None:
        group = self.api.http_get(f"/asset_groups/{asset_group_id}")
        current = list((group or {}).get("asset_group_assets") or [])
        merged = current + [
            asset_id for asset_id in asset_ids if asset_id not in current
        ]
        if merged == current:
            return
        self.api.http_put(
            f"/asset_groups/{asset_group_id}/assets",
            post_data={"asset_group_assets": merged},
        )

    def import_hosts(
        self, hosts: List[Dict], tag_name: str, asset_group_id: Optional[str] = None
    ) -> Dict:
        """Upsert one endpoint per resolved host; returns counts and the asset ids."""
        tag_id = self._tag_id(tag_name)
        asset_ids: List[str] = []
        failed: List[str] = []
        for host in dedupe_hosts(hosts):
            try:
                endpoint = self.api.endpoint.upsert(build_endpoint_input(host, tag_id))
            except Exception as err:
                self.logger.error(f"Endpoint upsert failed for {host['host']}: {err}")
                failed.append(host["host"])
                continue
            asset_id = (endpoint or {}).get("asset_id")
            if asset_id and asset_id not in asset_ids:
                asset_ids.append(asset_id)
        group_error = None
        if asset_group_id and asset_ids:
            try:
                self._add_to_asset_group(asset_group_id, asset_ids)
            except Exception as err:
                group_error = str(err)
                self.logger.error(f"Asset group update failed: {err}")
        return {
            "asset_ids": asset_ids,
            "failed": failed,
            "asset_group_error": group_error,
        }
