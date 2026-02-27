import json
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

from pyoaev.helpers import OpenAEVInjectorHelper

from injector_common.pagination import Pagination
from shodan.contracts import (
    CloudProviderAssetDiscovery,
    CriticalPortsAndExposedAdminInterface,
    CustomQuery,
    CVEEnumeration,
    CVESpecificWatchlist,
    DomainDiscovery,
    InjectorKey,
    IPEnumeration,
    ShodanContractId,
)
from shodan.models import (
    Asset,
    AssetExtendedAttributes,
    ConfigLoader,
    ContractType,
    NormalizeInputData,
)
from shodan.services import ShodanClientAPI, Utils

LOG_PREFIX = "[SHODAN_INJECTOR]"


class ShodanInjector:
    def __init__(self, config: ConfigLoader, helper: OpenAEVInjectorHelper):
        """Initialize the Injector with necessary configurations"""

        # Load configuration file and connection helper
        self.config = config
        self.helper = helper
        self.shodan_client_api = ShodanClientAPI(self.config, self.helper)
        self.utils = Utils()

    def _prepare_output_message(
        self, normalize_input_data: NormalizeInputData, results, user_info: dict
    ):
        self.helper.injector_logger.info(
            f"{LOG_PREFIX} - Start preparing the output message rendering.",
        )

        contract_name = normalize_input_data.contract_name
        targets = normalize_input_data.targets.model_dump()
        inject_content = normalize_input_data.inject_content.model_dump()

        #  Retrieving the contract-specific output trace configuration.
        output_trace_config = {
            "CLOUD_PROVIDER_ASSET_DISCOVERY": CloudProviderAssetDiscovery.output_trace_config(),
            "CRITICAL_PORTS_AND_EXPOSED_ADMIN_INTERFACE": CriticalPortsAndExposedAdminInterface.output_trace_config(),
            "CUSTOM_QUERY": CustomQuery.output_trace_config(),
            "CVE_ENUMERATION": CVEEnumeration.output_trace_config(),
            "CVE_SPECIFIC_WATCHLIST": CVESpecificWatchlist.output_trace_config(),
            "DOMAIN_DISCOVERY": DomainDiscovery.output_trace_config(),
            "IP_ENUMERATION": IPEnumeration.output_trace_config(),
        }
        if contract_name not in output_trace_config:
            self.helper.injector_logger.error(
                f"{LOG_PREFIX} - The contract name is unknown.",
                {"contract_name": contract_name},
            )
            raise ValueError(f"{LOG_PREFIX} - The contract name is unknown.")

        contract_output_trace_config = output_trace_config.get(contract_name)

        # Data Sections Info
        usage_limits = user_info.get("usage_limits", {})
        data_sections_info = {
            "plan": user_info.get("plan"),
            "scan_credits_remaining": f"{user_info.get('scan_credits')} / {usage_limits.get('scan_credits')}",
            "query_credits_remaining": f"{user_info.get('query_credits')} / {usage_limits.get('query_credits')}",
        }

        # Data Section External API
        results_data = results.get("data")

        rendering_output_message = self.utils.generate_output_message(
            output_trace_config=contract_output_trace_config,
            data_sections_config=[inject_content, targets],
            data_sections_info=[data_sections_info],
            data_sections_external_api=results_data,
            auto_create_assets=inject_content.get("auto_create_assets", None),
        )
        self.helper.injector_logger.info(
            f"{LOG_PREFIX} - Finalization of the preparation of the output message rendering.",
        )
        return rendering_output_message

    @staticmethod
    def _aggregate_assets(found_assets_list: list[dict]):
        merged = {}

        for asset_dict in found_assets_list:
            extended_attributes = asset_dict.get("extended_attributes", {})

            hostname = asset_dict.get("name")
            platform = extended_attributes.get("platform")
            arch = extended_attributes.get("arch")

            key = (hostname, platform, arch)
            ips = set(extended_attributes.get("ip_addresses", []))

            if key not in merged:
                merged[key] = asset_dict
                merged[key]["extended_attributes"]["ip_addresses"] = ips
            else:
                merged[key]["extended_attributes"]["ip_addresses"].update(ips)

        for asset in merged.values():
            asset["extended_attributes"]["ip_addresses"] = list(
                asset["extended_attributes"]["ip_addresses"]
            )

        return list(merged.values())

    def _prepare_output_structured(self, shodan_results: dict):

        results = shodan_results.get("data", [])
        found_assets_list = []

        for item in results:
            result = item.get("result", {})

            raw_api_url = item.get("url")
            url = raw_api_url.split(maxsplit=1)[1] if raw_api_url else ""
            parsed_url = urlparse(url)
            origin_url = (
                f"https://www.shodan.io/search?{parsed_url.query}"
                if parsed_url.query
                else ""
            )

            if "matches" in result:
                elements = result.get("matches", [])
            elif "data" in result:
                elements = result.get("data", [])  # For CVE_SPECIFIC_WATCHLIST CONTRACT
            else:
                elements = []

            for element in elements:

                ip_str = element.get("ip_str")
                hostnames = element.get("hostnames", [])
                os = element.get("os", "Unknown")

                if not ip_str or not hostnames:
                    continue

                for hostname in hostnames:

                    asset_extended_attributes = AssetExtendedAttributes(
                        ip_addresses=[ip_str],
                        platform=os,
                        hostname=hostname,
                    )

                    asset = Asset(
                        name=hostname,
                        description=f"Asset automatically created by Shodan Injector."
                        f"Origin url: {origin_url}",
                        tags=["source:shodan.io"],
                        extended_attributes=asset_extended_attributes,
                    )

                    found_assets_list.append(asset.model_dump())

        aggregate_assets = self._aggregate_assets(found_assets_list)
        return {"found_assets": aggregate_assets}

    def _resolve_assets(self, data: dict, selector_key: str) -> list[dict]:

        if selector_key == "assets":
            return data.get("assets", [])

        if selector_key == "asset-groups":
            asset_groups = data.get("assetGroups", [])
            asset_group_ids = [
                asset_group.get("asset_group_id") for asset_group in asset_groups
            ]

            return Pagination.fetch_all_targets(
                helper=self.helper,
                asset_group_ids=asset_group_ids,
            )

        return []

    def _deduplicate(self, key: str, values: list[str]):

        if not values:
            return values

        deduplicate_values = []
        removed_values = []
        for value in values:
            if value in deduplicate_values:
                removed_values.append(value)
            else:
                deduplicate_values.append(value)

        if removed_values:
            self.helper.injector_logger.debug(
                f"{LOG_PREFIX} - Deduplication was performed on list {key}.",
                {"key": key, "removed_values": removed_values},
            )

        return deduplicate_values

    def _build_targets_from_assets(
        self, selector_property: str, targets: dict, assets: list[dict]
    ):

        match selector_property:
            case "automatic":
                targets["asset_ids"] = [asset.get("asset_id") for asset in assets]

                targets["hostnames"] = [
                    asset.get("endpoint_hostname")
                    for asset in assets
                    if asset and asset.get("endpoint_hostname")
                ]

                targets["ips"] = [
                    endpoint_ip
                    for asset in assets
                    for endpoint_ip in (asset.get("endpoint_ips") or [])
                ]

                targets["seen_ips"] = [
                    asset.get("endpoint_seen_ip")
                    for asset in assets
                    if asset and asset.get("endpoint_seen_ip")
                ]

                for asset in assets:
                    targets["assets"].append(
                        {
                            "asset_id": asset.get("asset_id"),
                            "endpoint_hostname": asset.get("endpoint_hostname") or None,
                            "endpoint_ips": asset.get("endpoint_ips") or [],
                            "endpoint_seen_ip": asset.get("endpoint_seen_ip"),
                        }
                    )

            # Only the hostname is used
            case "hostname":
                for asset in assets:
                    asset_id = asset.get("asset_id")
                    endpoint_hostname = asset.get("endpoint_hostname")
                    if endpoint_hostname:
                        targets["asset_ids"].append(asset_id)
                        targets["hostnames"].append(endpoint_hostname)
                    else:
                        self.helper.injector_logger.debug(
                            f"{LOG_PREFIX} - The asset ID was ignored because you chose to map to hostname, "
                            f"but the asset does not have a hostname value.",
                            {
                                "selector_property": selector_property,
                                "asset_id": asset_id,
                            },
                        )

                    targets["assets"].append(
                        {
                            "asset_id": asset_id,
                            "endpoint_hostname": endpoint_hostname,
                            "endpoint_ips": [],
                            "endpoint_seen_ip": None,
                        }
                    )

            # Only the local_ip (first) is used (only first IP used)
            case "local_ip":
                for asset in assets:
                    asset_id = asset.get("asset_id")
                    endpoint_ips = asset.get("endpoint_ips")
                    if endpoint_ips:
                        targets["asset_ids"].append(asset_id)
                        targets["ips"].append(endpoint_ips[0])
                        targets["assets"].append(
                            {
                                "asset_id": asset_id,
                                "endpoint_hostname": None,
                                "endpoint_ips": endpoint_ips,
                                "endpoint_seen_ip": None,
                            }
                        )
                    else:
                        self.helper.injector_logger.debug(
                            f"{LOG_PREFIX} - The asset ID was ignored because you chose to map to local_ip (first), "
                            f"but the asset does not have a ip value.",
                            {
                                "selector_property": selector_property,
                                "asset_id": asset_id,
                            },
                        )

            # Only the seen_ip is used
            case "seen_ip":
                for asset in assets:
                    asset_id = asset.get("asset_id")
                    endpoint_seen_ip = asset.get("endpoint_seen_ip")
                    if endpoint_seen_ip:
                        targets["asset_ids"].append(asset_id)
                        targets["seen_ips"].append(endpoint_seen_ip)
                        targets["assets"].append(
                            {
                                "asset_id": asset_id,
                                "endpoint_hostname": None,
                                "endpoint_ips": [],
                                "endpoint_seen_ip": endpoint_seen_ip,
                            }
                        )
                    else:
                        self.helper.injector_logger.debug(
                            f"{LOG_PREFIX} - The asset ID was ignored because you chose to map to seen_ip, "
                            f"but the asset does not have a seen_ip value.",
                            {
                                "selector_property": selector_property,
                                "asset_id": asset_id,
                            },
                        )
        return targets

    def _normalize_input_data(
        self,
        data: dict,
        inject_content: dict,
        selector_key: str,
        selector_property: str = None,
    ):

        # Contract information
        contract_id = data["injection"]["inject_injector_contract"]["convertedContent"][
            "contract_id"
        ]
        contract = ContractType(ShodanContractId(contract_id).name.lower())
        inject_content["contract"] = contract.value

        self.helper.injector_logger.info(
            f"{LOG_PREFIX} - Starting the normalization and validation of input data...",
            {
                "contract_id": contract_id,
                "contract_name": contract.name,
                "type_of_target": selector_key,
            },
        )

        if selector_key not in ["manual", "assets", "asset-groups"]:
            self.helper.injector_logger.error(
                f"{LOG_PREFIX} - Invalid selector key, expected keys 'manual', 'assets', or 'asset-groups",
                {"selector_key": selector_key},
            )
            raise ValueError(
                f"{LOG_PREFIX} - Invalid selector key, expected keys 'manual', 'assets', or 'asset-groups'."
            )

        initial_targets = {
            "selector_key": selector_key,
            "asset_ids": [],
            "hostnames": [],
            "ips": [],
            "seen_ips": [],
            "assets": [],
        }

        if selector_key == "manual":
            normalize_input_data = NormalizeInputData.model_validate(
                {
                    "contract_name": contract.name,
                    "contract_id": contract_id,
                    "inject_content": inject_content,
                    "targets": initial_targets,
                }
            )
            self.helper.injector_logger.info(
                f"{LOG_PREFIX} - Finalization the normalization and validation of input data.",
            )
            return normalize_input_data

        # Resolve Assets (assets / asset-groups)
        assets = self._resolve_assets(data, selector_key)

        # Build targets from assets based on the selector_property
        targets = self._build_targets_from_assets(
            selector_property, initial_targets, assets
        )

        # Deduplication of hostnames, ips, and seen_ips
        for key in ("hostnames", "ips", "seen_ips"):
            targets[key] = self._deduplicate(key=key, values=targets[key])

        normalize_input_data = NormalizeInputData.model_validate(
            {
                "contract_name": contract.name,
                "contract_id": contract_id,
                "inject_content": inject_content,
                "targets": targets,
            }
        )

        self.helper.injector_logger.info(
            f"{LOG_PREFIX} - Finalization the normalization and validation of input data.",
        )
        return normalize_input_data

    def _shodan_execution(self, data: dict):

        inject_content = data["injection"]["inject_content"]
        selector_key = inject_content[InjectorKey.TARGET_SELECTOR_KEY]
        selector_property = inject_content[InjectorKey.TARGET_PROPERTY_SELECTOR_KEY]

        # Normalization and Validation of input data (Manual / Assets / Asset-Groups)
        normalize_input_data = self._normalize_input_data(
            data, inject_content, selector_key, selector_property
        )

        # Preparation and creation of HTTP requests based on contracts
        shodan_results, shodan_credit_user = (
            self.shodan_client_api.process_shodan_search(normalize_input_data)
        )

        # Preparation and creation of auto_create_assets
        output_structured = ""
        if normalize_input_data.inject_content.auto_create_assets:
            output_structured = self._prepare_output_structured(shodan_results)

        # Preparation and creation of output_message
        output_message = self._prepare_output_message(
            normalize_input_data, shodan_results, shodan_credit_user
        )
        return output_structured, output_message

    def process_message(self, data: dict) -> None:
        # Initialization to get the current start utc iso format.
        start_utc_isoformat = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self.helper.injector_logger.info(
            f"{LOG_PREFIX} - Triggering of the Shodan injector...",
            {
                "start_utc_isoformat": start_utc_isoformat,
            },
        )
        start = time.time()
        inject_id = data["injection"]["inject_id"]

        # Notify API of reception and expected number of operations
        reception_data = {"tracking_total_count": 1}
        self.helper.api.inject.execution_reception(
            inject_id=inject_id, data=reception_data
        )

        # Execute inject
        try:
            output_structured, output_message = self._shodan_execution(data)
            execution_duration = int(time.time() - start)
            callback_data = {
                "execution_message": output_message,
                "execution_output_structured": json.dumps(output_structured),
                "execution_status": "SUCCESS",
                "execution_duration": execution_duration,
                "execution_action": "complete",
            }
            self.helper.api.inject.execution_callback(
                inject_id=inject_id, data=callback_data
            )
            self.helper.injector_logger.info(
                f"{LOG_PREFIX} - The injector has completed its execution.",
                {"execution_duration": f"{execution_duration}s"},
            )

        except Exception as err:
            self.helper.injector_logger.error(
                f"{LOG_PREFIX} - An error has occurred", {"error": str(err)}
            )
            callback_data = {
                "execution_message": str(err),
                "execution_status": "ERROR",
                "execution_duration": int(time.time() - start),
                "execution_action": "complete",
            }
            self.helper.api.inject.execution_callback(
                inject_id=inject_id, data=callback_data
            )

    def start(self):
        self.helper.listen(message_callback=self.process_message)
