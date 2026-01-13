import time
from datetime import datetime, timezone
from shodan.contracts import InjectorKey, ShodanContractId
from shodan.services import ShodanClientAPI
from shodan.models import ConfigLoader
from pyoaev.helpers import OpenAEVInjectorHelper
LOG_PREFIX = "[SHODAN_INJECTOR]"

class ShodanInjector:
    def __init__(self, config: ConfigLoader, helper: OpenAEVInjectorHelper):
        """Initialize the Injector with necessary configurations"""

        # Load configuration file and connection helper
        self.config = config
        self.helper = helper

    def _shodan_execution(self, start, inject_id, data):

        contract_id = data["injection"]["inject_injector_contract"]["convertedContent"]["contract_id"]
        contract_name = ShodanContractId(contract_id).name

        inject_content = data["injection"]["inject_content"]
        selector_key = inject_content[InjectorKey.TARGET_SELECTOR_KEY]


        if selector_key == "manual":
            shodan_api = ShodanClientAPI.get_shodan_search(contract_name, inject_content)

        elif selector_key == "assert":
            selector_property = inject_content[InjectorKey.TARGET_PROPERTY_SELECTOR_KEY]

        elif selector_key == "assert-groups":
            selector_property = inject_content[InjectorKey.TARGET_PROPERTY_SELECTOR_KEY]

        else:
            return None

        return []

    def process_message(self, data: dict) -> None:
        # Initialization to get the current start utc iso format.
        start_utc_isoformat = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self.helper.injector_logger.info(
            f"{LOG_PREFIX} - Starting injector...",
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
            result = self._shodan_execution(start, inject_id, data)
            callback_data = {
                # "execution_message": result["message"],
                # "execution_output_structured": json.dumps(result["outputs"]),
                "execution_status": "SUCCESS",
                "execution_duration": int(time.time() - start),
                "execution_action": "complete",
            }
            self.helper.api.inject.execution_callback(
                inject_id=inject_id, data=callback_data
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
