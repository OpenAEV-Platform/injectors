import uuid
from typing import Dict, List, Optional

from dns_enum.contracts.dns_enum_constants import (
    ENDPOINT_TAG_COLOR,
    EXTERNAL_REFERENCE_PREFIX,
)
from dns_enum.helpers.asset_classifier import (
    classify,
    is_unclassified,
    is_web,
    shared_addresses,
)

# Size of one page of the platform's endpoint search (the API allows 1,000).
SEARCH_PAGE_SIZE = 500
# Values per filter of one search, so a large run never sends an unbounded filter.
SEARCH_CHUNK = 200


def external_reference(hostname: str) -> str:
    """Stable reference of a discovered host: the platform's upsert matches on it
    first, so a rerun updates the same endpoint instead of creating a second one."""
    return EXTERNAL_REFERENCE_PREFIX + hostname.strip().rstrip(".").lower()


def is_own_asset(asset: Dict) -> bool:
    """True for an asset this injector created (its external reference)."""
    return str(asset.get("asset_external_reference") or "").startswith(
        EXTERNAL_REFERENCE_PREFIX
    )


def build_endpoint_input(
    host: Dict, tag_id: Optional[str], classification: Optional[Dict] = None
) -> Dict:
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
    if classification:
        endpoint.update(classification)
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


def _filter(key: str, values: List[str]) -> Dict:
    return {
        "id": str(uuid.uuid4()),
        "key": key,
        "mode": "or",
        "operator": "eq",
        "values": values,
    }


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

    def _search(self, key: str, values: List[str]) -> List[Dict]:
        """Every asset (any category) whose `key` equals one of `values`, all pages
        read, through the unified inventory search of the platform."""
        found: List[Dict] = []
        for start in range(0, len(values), SEARCH_CHUNK):
            chunk = values[start : start + SEARCH_CHUNK]
            page = 0
            while True:
                result = self.api.http_post(
                    "/assets/search",
                    post_data={
                        "page": page,
                        "size": SEARCH_PAGE_SIZE,
                        "filterGroup": {
                            "mode": "and",
                            "filters": [_filter(key, chunk)],
                        },
                    },
                )
                content = list((result or {}).get("content") or [])
                found.extend(content)
                if (result or {}).get("last", True) or len(content) < SEARCH_PAGE_SIZE:
                    break
                page += 1
        return found

    def _existing_by_reference(self, hosts: List[Dict]) -> Dict[str, Dict]:
        references = [external_reference(host["host"]) for host in hosts]
        return {
            asset.get("asset_external_reference"): asset
            for asset in self._search("asset_external_reference", references)
            if asset.get("asset_external_reference")
        }

    def _foreign_owner(
        self, ip: str, cache: Dict[str, Optional[Dict]]
    ) -> Optional[Dict]:
        """The first asset on `ip` this injector did not create, if any."""
        if ip not in cache:
            cache[ip] = next(
                (
                    asset
                    for asset in self._search("asset_ips", [ip])
                    if asset.get("asset_id") and not is_own_asset(asset)
                ),
                None,
            )
        return cache[ip]

    def _owner_of(self, host: Dict, cache: Dict[str, Optional[Dict]]) -> Optional[Dict]:
        """The asset another source created on one of the host's addresses."""
        for ip in host["ips"]:
            owner = self._foreign_owner(ip, cache)
            if owner:
                return owner
        return None

    def import_hosts(
        self,
        hosts: List[Dict],
        tag_name: str,
        asset_group_id: Optional[str] = None,
        classify_assets: bool = True,
    ) -> Dict:
        """Upsert one endpoint per resolved host; returns counts and the asset ids.

        A host on the address of an asset another source created (a collector, an
        agent, a person) is attached to that asset and never upserted: the platform's
        upsert matches on hostname + IP, so sending it could rename or reclassify that
        asset. A host whose addresses cannot be checked is skipped for the same reason.

        With classify_assets on, each other host gets the category its addresses give
        it (asset_classifier), filled only on an asset nobody classified yet.
        """
        tag_id = self._tag_id(tag_name)
        unique = dedupe_hosts(hosts)
        asset_ids: List[str] = []
        failed: List[str] = []
        attached: List[str] = []
        skipped: List[str] = []
        web = 0
        servers = 0
        lookup_error = None
        existing: Dict[str, Dict] = {}
        shared = shared_addresses(unique) if classify_assets else set()
        if classify_assets:
            try:
                existing = self._existing_by_reference(unique)
            except Exception as err:  # never classify blind: import unclassified
                lookup_error = str(err)
                self.logger.error(f"Existing endpoint lookup failed: {err}")
        owners: Dict[str, Optional[Dict]] = {}
        for host in unique:
            try:
                owner = self._owner_of(host, owners)
            except Exception as err:  # never upsert blind over another source
                self.logger.error(f"Address lookup failed for {host['host']}: {err}")
                skipped.append(host["host"])
                continue
            if owner:
                attached.append(
                    f"{host['host']} -> {owner.get('asset_name') or owner['asset_id']}"
                )
                if owner["asset_id"] not in asset_ids:
                    asset_ids.append(owner["asset_id"])
                continue
            classification = None
            if classify_assets and lookup_error is None:
                reference = external_reference(host["host"])
                if is_unclassified(existing.get(reference)):
                    classification = classify(host, shared)
            try:
                endpoint = self.api.endpoint.upsert(
                    build_endpoint_input(host, tag_id, classification)
                )
            except Exception as err:
                self.logger.error(f"Endpoint upsert failed for {host['host']}: {err}")
                failed.append(host["host"])
                continue
            if is_web(classification):
                web += 1
            elif classification:
                servers += 1
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
            "web_applications": web,
            "servers": servers,
            "attached": attached,
            "skipped": skipped,
            "lookup_error": lookup_error,
        }
