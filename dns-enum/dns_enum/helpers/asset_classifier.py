"""Classification of discovered hosts into OpenAEV asset categories.

A name that shares an address with other discovered names (virtual hosts behind one
ingress or load balancer), or whose CNAME points at a CDN, is a web application
reached by its name: category WEB_APPLICATION, subcategory WEBSITE, asset_url
https://<name>. A name alone on its addresses is a host: category HOST, subcategory
SERVER. The values are the OpenAEV enums AssetCategory and AssetSubCategory
(openaev-model, io.openaev.database.model).
"""

from typing import Dict, Iterable, List, Optional

WEB_CATEGORY = "WEB_APPLICATION"
WEB_SUBCATEGORY = "WEBSITE"
HOST_CATEGORY = "HOST"
HOST_SUBCATEGORY = "SERVER"

# CNAME targets of the common CDN and edge networks: a name pointing at one of them
# is a web front, whatever its address.
CDN_CNAME_SUFFIXES = (
    "akadns.net",
    "akamai.net",
    "akamaiedge.net",
    "akamaihd.net",
    "azureedge.net",
    "azurefd.net",
    "b-cdn.net",
    "cdn.cloudflare.net",
    "cdn77.org",
    "cloudfront.net",
    "edgecastcdn.net",
    "edgekey.net",
    "edgesuite.net",
    "fastly.net",
    "fastlylb.net",
    "ghs.googlehosted.com",
    "impervadns.net",
    "incapdns.net",
    "llnwd.net",
    "stackpathdns.com",
)

# Categories an injector may replace: none set yet, or the platform's defaults.
_UNCLASSIFIED_CATEGORIES = (None, "", HOST_CATEGORY, "GENERIC_ASSET")


def _normalise(name: str) -> str:
    return str(name or "").strip().rstrip(".").lower()


def is_cdn_cname(targets: Iterable[str]) -> bool:
    for target in targets or []:
        value = _normalise(target)
        for suffix in CDN_CNAME_SUFFIXES:
            if value == suffix or value.endswith("." + suffix):
                return True
    return False


def shared_addresses(hosts: List[Dict]) -> set:
    """The addresses two or more distinct discovered names resolve to."""
    names_by_ip: Dict[str, set] = {}
    for host in hosts:
        for ip in host.get("ips") or []:
            names_by_ip.setdefault(ip, set()).add(_normalise(host["host"]))
    return {ip for ip, names in names_by_ip.items() if len(names) > 1}


def classify(host: Dict, shared: set) -> Dict:
    """The classification fields of one host for the endpoint upsert."""
    name = _normalise(host["host"])
    cnames = (host.get("records") or {}).get("CNAME") or []
    if is_cdn_cname(cnames) or any(ip in shared for ip in host.get("ips") or []):
        return {
            "asset_category": WEB_CATEGORY,
            "asset_subcategory": WEB_SUBCATEGORY,
            "asset_url": f"https://{name}",
        }
    return {"asset_category": HOST_CATEGORY, "asset_subcategory": HOST_SUBCATEGORY}


def is_web(classification: Optional[Dict]) -> bool:
    return bool(classification) and classification["asset_category"] == WEB_CATEGORY


def is_unclassified(asset: Optional[Dict]) -> bool:
    """True when nobody classified the asset yet, so the injector may fill it.

    An asset whose subcategory is set, or whose category is anything but the platform
    default (HOST) or the to-classify bucket, was classified by a person or by an
    earlier run: it is left as it is.
    """
    if asset is None:
        return True
    if asset.get("asset_subcategory"):
        return False
    return asset.get("asset_category") in _UNCLASSIFIED_CATEGORIES
