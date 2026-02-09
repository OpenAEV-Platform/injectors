import time
from datetime import datetime, timezone

from pyoaev.helpers import OpenAEVInjectorHelper

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
from shodan.models import ConfigLoader
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
        self, contract_name: str, inject_content: dict, results, user_info: dict
    ):
        self.helper.injector_logger.info(
            f"{LOG_PREFIX} - Start preparing the output message rendering.",
        )
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
            data_sections_config=[inject_content],
            data_sections_info=[data_sections_info],
            data_sections_external_api=results_data,
            auto_create_assets=inject_content.get("auto_create_assets", None),
        )
        self.helper.injector_logger.info(
            f"{LOG_PREFIX} - Finalization of the preparation of the output message rendering.",
        )
        return rendering_output_message

    def _shodan_execution(self, data):

        # Contract information
        contract_id = data["injection"]["inject_injector_contract"]["convertedContent"][
            "contract_id"
        ]
        contract_name = ShodanContractId(contract_id).name

        inject_content = data["injection"]["inject_content"]
        selector_key = inject_content[InjectorKey.TARGET_SELECTOR_KEY]

        self.helper.injector_logger.info(
            f"{LOG_PREFIX} - Starting the execution of Shodan...",
            {
                "contract_id": contract_id,
                "contract_name": contract_name,
                "type_of_target": selector_key,
            },
        )
        if selector_key == "manual":
            shodan_results, shodan_credit_user = (
                self.shodan_client_api.process_shodan_search(
                    contract_id, inject_content
                )
            )

            output_json = ""
            output_message = self._prepare_output_message(
                contract_name, inject_content, shodan_results, shodan_credit_user
            )
            return output_json, output_message

        elif selector_key == "assets":
            output_json = ""
            output_message = "Assets - Currently not supported"
            return output_json, output_message

        elif selector_key == "asset-groups":
            output_json = ""
            output_message = "Asset-groups - Currently not supported"
            return output_json, output_message

        else:
            self.helper.injector_logger.error(
                f"{LOG_PREFIX} - Invalid selector key, expected keys 'manual', 'assets', or 'asset-groups",
                {"selector_key": selector_key},
            )
            raise ValueError(
                f"{LOG_PREFIX} - Invalid selector key, expected keys 'manual', 'assets', or 'asset-groups'."
            )

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
            output_json, output_message = self._shodan_execution(data)
            execution_duration = int(time.time() - start)
            callback_data = {
                "execution_message": output_message,
                # "execution_output_structured": json.dumps(result["outputs"]),
                "execution_status": "SUCCESS",
                "execution_duration": execution_duration,
                "execution_action": "complete",
            }
            self.helper.api.inject.execution_callback(
                inject_id=inject_id, data=callback_data
            )
            self.helper.injector_logger.info(
                f"{LOG_PREFIX} - The injector has completed its execution.",
                {"execution_duration": f"{execution_duration} s"},
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
