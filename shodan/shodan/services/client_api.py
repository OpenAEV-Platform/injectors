from typing import Any, Union
from urllib.parse import quote_plus, urljoin

import requests
from limiter import Limiter
from pyoaev.helpers import OpenAEVInjectorHelper
from tenacity import RetryError, retry, stop_after_attempt, wait_exponential_jitter

from shodan.models import (
    ConfigLoader,
    ContractHTTPDefinition,
    FilterDefinition,
    InjectContentType,
    InvalidContractError,
    InvalidTargetFieldError,
    InvalidTargetPropertySelectorError,
    MissingRequiredFieldError,
    NormalizeInputData,
    NoTargetsRecovered,
    Operator,
    ShodanRestAPI,
    TargetsType,
)

LOG_PREFIX = "[SHODAN_CLIENT_API]"


class ShodanClientAPI:
    def __init__(self, config: ConfigLoader, helper: OpenAEVInjectorHelper):
        """Initialize the Injector with necessary configurations"""

        # Load configuration file and connection helper
        self.config = config
        self.helper = helper

        self.base_url = self.config.shodan.base_url
        self.api_key = self.config.shodan.api_key

        self.api_retry = self.config.shodan.api_retry
        self.api_backoff = self.config.shodan.api_backoff.total_seconds()

        # Limiter config
        self.rate_limiter = Limiter(
            rate=self.config.shodan.api_leaky_bucket_rate,
            capacity=self.config.shodan.api_leaky_bucket_capacity,
            bucket="shodan",
        )

    @staticmethod
    def _secure_url(url: str) -> str:
        """Removes the API key from a URL for logging or display purposes.
        This is necessary to prevent the Shodan API key from being exposed in logs or debug output.
        Args:
            url (str): The URL potentially containing an API key.
        Returns:
            str: The URL without the API key.
        """

        if not url:
            return url
        if "?query" in url:
            return url.split("&key=")[0]
        return url.split("?key=")[0]

    @staticmethod
    def _build_query(query_params: dict[str, tuple[str, Operator]]) -> str:
        """Constructs a Shodan query string from filter parameters.
        Each item in `query_params` is a tuple of (value, operator) where operator can be 'and', 'or', or None.
        The resulting string is used for use in the Shodan search URL.

        Args:
            query_params (dict[str, tuple[str, Operator]]): Dictionary mapping filter keys to (value, operator).

        Returns:
            str: A Shodan query string.
        """

        query = ["query="]
        for key, (value, operator) in query_params.items():
            if operator == "and":
                query.append(f"{key}:{value} ")
            elif operator == "or":
                query.append(f"{key}:{value},")
            else:
                query.append(f"{key}:{value}")
                break
        return "".join(query).strip()

    def _build_url(
        self,
        endpoint: str,
        query_params: str | None = None,
        is_custom_query: bool = False,
    ) -> str:
        """Builds a full Shodan API URL including the endpoint, query parameters, and API key.

        Args:
            endpoint (str): The API endpoint (relative path).
            query_params (str | None): Encoded query string to append to the URL.
            is_custom_query (bool): Whether the query is a custom query requiring special handling.

        Returns:
            str: Fully constructed URL ready to be requested.
        """

        url = urljoin(self.base_url, endpoint)
        api_key = f"key={self.api_key.get_secret_value()}"
        if not query_params and "?query=" not in url:
            return f"{url}?{api_key}"
        if is_custom_query and "?query=" in url:
            return f"{url}&{api_key}"
        return f"{url}?{query_params}&{api_key}"

    # SECTION INFO
    def _get_user_info(self) -> dict[str, Any]:
        """Retrieves the user's Shodan account information and quota.

        Returns:
            dict[str, Any]: Dictionary containing user account information from Shodan.
        """
        self.helper.injector_logger.info(
            f"{LOG_PREFIX} - Preparation for user quota recovery...",
        )

        return self._process_request(
            raw_input=["user_info"],
            request_api=ShodanRestAPI.API_PLAN_INFORMATION,
        )

    def _process_request(
        self,
        raw_input: list[str] | str,
        request_api: ShodanRestAPI | None,
        filters_template: dict[str, FilterDefinition] | None = None,
        is_custom_query: bool = False,
        http_method_custom_query: str | None = None,
    ) -> Union[dict[str, Any], Any]:
        """Sends a request to Shodan for the given targets and filters, handling retries and errors.
        This method constructs the query URL, applies optional filters, encodes it, and calls "_request_data".

        Args:
            raw_input (list[str] | str): List of targets or a single target string.
            request_api (ShodanRestAPI | None): The API endpoint definition to use.
            filters_template (dict[str, FilterDefinition] | None): Optional filters to apply to the query.
            is_custom_query (bool): Whether this is a custom query bypassing standard contract endpoints.
            http_method_custom_query (str | None): HTTP method to use for a custom query.

        Returns:
             Union[dict[str, Any], Any]: Either a structured dictionary with targets and results, or the raw API
                response for special queries.
        """

        targets = [raw_input] if is_custom_query else raw_input
        http_method = (
            http_method_custom_query
            if is_custom_query
            else request_api.value.http_method
        )
        endpoint_template = raw_input if is_custom_query else request_api.value.endpoint

        result = None
        results = []
        for target in targets:
            new_endpoint = endpoint_template
            query_params = None
            encoded_for_shodan = None

            if filters_template:
                filters_dict = {}
                for key, filter_definition in filters_template.items():
                    if isinstance(filter_definition.value, list):
                        value_resolved = ",".join(
                            str(v) for v in filter_definition.value
                        )
                    elif (
                        isinstance(filter_definition.value, str)
                        and "{target}" in filter_definition.value
                    ):
                        value_resolved = filter_definition.value.format(target=target)
                    else:
                        value_resolved = filter_definition.value

                    filters_dict[key] = (value_resolved, filter_definition.operator)

                query_params = self._build_query(filters_dict)
                encoded_for_shodan = quote_plus(query_params, safe="=:,*.")

            target_url = self._build_url(
                endpoint=new_endpoint,
                query_params=encoded_for_shodan if filters_template else query_params,
                is_custom_query=is_custom_query,
            )

            try:
                result = self._request_data(
                    method=http_method,
                    url=target_url,
                )
                results.append(
                    {
                        "target": target,
                        "url": f"{http_method} {self._secure_url(target_url)}",
                        "result": result,
                    }
                )
            except RetryError as retry_exc:
                inner_exception = retry_exc.last_attempt.exception()

                request = inner_exception.request
                request_filtered = {
                    "method": request.method,
                    "url": f"{http_method} {self._secure_url(target_url)}",
                }

                response = inner_exception.response
                response_filtered = {
                    "status_code": response.status_code,
                    "reason": response.reason,
                    "error": response.text,
                }

                results.append(
                    {
                        "target": target,
                        "is_error": True,
                        "request": request_filtered,
                        "response": response_filtered,
                    }
                )
        return (
            result
            if targets == ["user_info"]
            else {"targets": targets, "data": results}
        )

    def _request_data(self, method: str, url: str) -> dict[str, Any]:
        """Sends an HTTP request to the given URL using the specified method, with built-in retry and rate limiting
        mechanisms.

        Args:
            method (str): The HTTP method to use for the request.
            url (str): The full URL to send the request to.

        Returns:
            dict[str, Any]: The parsed JSON response from the API.

        Raises:
            tenacity.RetryError: If all retry attempts fail.
        """

        @retry(
            stop=stop_after_attempt(max_attempt_number=self.api_retry),
            wait=wait_exponential_jitter(
                initial=1, max=self.api_backoff, exp_base=2, jitter=1
            ),
        )
        def _retry_wrapped():
            response = requests.request(method=method, url=url)
            response.raise_for_status()
            return response.json()

        with self.rate_limiter:
            return _retry_wrapped()

    def _execute_contract(
        self,
        inject_content: InjectContentType,
        targets: TargetsType,
        contract_http_definition: ContractHTTPDefinition,
    ) -> dict[str, Any]:
        """Execute a Shodan contract based on the provided inject content and targets.

        This method resolves the targets depending on the target selector:
        - If `manual`, it validates that all required fields in the contract are provided in `inject_content`.
          If the contract is a `custom_query`, it directly processes the custom query.
        - If `automatic`, it selects the targets based on the `target_property_selector` and `target_field`.

        Once targets are resolved, the method invokes `_process_request` to query Shodan
        and return the structured results.

        Args:
            inject_content (InjectContentType): Object containing information injected by the user.
            targets (TargetsType): targets contains target information if assets or asset-groups, or is empty if manual.
            contract_http_definition (ContractHTTPDefinition): Object containing the definition of the selected contract.

        Returns:
            dict[str, Any]: Dictionary containing the results of the Shodan search.
        """
        target_selector = inject_content.target_selector
        target_field = contract_http_definition.target_field
        required_fields = contract_http_definition.required_fields

        if target_selector == "manual":
            for required_field in required_fields:
                field = getattr(inject_content, required_field, None)
                if field in (None, "", []):
                    self.helper.injector_logger.error(
                        f"{LOG_PREFIX} - The field is required and cannot be empty.",
                        {"required_field": required_field},
                    )
                    raise MissingRequiredFieldError(
                        f"{LOG_PREFIX} - The field is required and cannot be empty."
                    )

            resolved_targets = getattr(inject_content, target_field, None)

            if inject_content.contract == "custom_query":
                return self._process_request(
                    raw_input=inject_content.custom_query,
                    request_api=None,
                    filters_template=None,
                    is_custom_query=True,
                    http_method_custom_query=inject_content.http_method,
                )
        else:
            target_property_selector = inject_content.target_property_selector
            mapping_target_property = {
                "ip": {
                    "automatic": targets.ips + targets.seen_ips,
                    "local_ip": targets.ips,
                    "seen_ip": targets.seen_ips,
                },
                "hostname": {
                    "automatic": targets.hostnames,
                    "hostname": targets.hostnames,
                },
            }

            if target_field not in mapping_target_property:
                self.helper.injector_logger.error(
                    f"{LOG_PREFIX} - Invalid target field.",
                    {"target_field": target_field},
                )
                raise InvalidTargetFieldError(f"{LOG_PREFIX} - Invalid target field.")

            available_targets = mapping_target_property.get(target_field)
            if target_property_selector not in available_targets:
                self.helper.injector_logger.error(
                    f"{LOG_PREFIX} - Invalid target property selector.",
                    {"target_property_selector": target_property_selector},
                )
                raise InvalidTargetPropertySelectorError(
                    f"{LOG_PREFIX} - Invalid target property selector."
                )

            resolved_targets = available_targets.get(target_property_selector)

        if not resolved_targets:
            self.helper.injector_logger.error(
                f"{LOG_PREFIX} - No targets were recovered for the contract.",
            )
            raise NoTargetsRecovered(
                f"{LOG_PREFIX} - No targets were recovered for the contract."
            )

        return self._process_request(
            raw_input=resolved_targets,
            request_api=ShodanRestAPI.SEARCH_SHODAN,
            filters_template=contract_http_definition.filters,
        )

    def _get_contract_http_definition(
        self, inject_content: InjectContentType
    ) -> ContractHTTPDefinition:
        """Retrieves the HTTP contract definition corresponding to the injected content.
            This method selects the appropriate HTTP contract from a list of predefined contracts, based on the value
            of inject_content.contract.

        Args:
            inject_content (InjectContentType): Object containing information injected by the user, including the
                contract name and possible fields such as organization, port, vulnerability or cloud_provider.

        Returns:
            ContractHTTPDefinition: Object containing the complete definition of the selected contract, with the
                required fields and associated filters.
        """

        hostname_and_org_filters = {
            "hostname": FilterDefinition(
                value="{target},*.{target}",
                operator=Operator.OR,
            ),
            "org": FilterDefinition(
                value=getattr(inject_content, "organization", []) or "{target}",
            ),
        }

        contract_http_definitions = {
            "domain_discovery": ContractHTTPDefinition(
                required_fields=["hostname"],
                filters={
                    **hostname_and_org_filters,
                },
            ),
            "ip_enumeration": ContractHTTPDefinition(
                target_field="ip",
                required_fields=["ip"],
                filters={
                    "ip": FilterDefinition(
                        value="{target}",
                    )
                },
            ),
            "cve_enumeration": ContractHTTPDefinition(
                required_fields=["hostname"],
                filters={
                    "has_vuln": FilterDefinition(value="true", operator=Operator.AND),
                    **hostname_and_org_filters,
                },
            ),
            "cve_specific_watchlist": ContractHTTPDefinition(
                required_fields=["vulnerability", "hostname"],
                filters={
                    "vuln": FilterDefinition(
                        value=getattr(inject_content, "vulnerability", []),
                        operator=Operator.AND,
                    ),
                    **hostname_and_org_filters,
                },
            ),
            "critical_ports_and_exposed_admin_interface": ContractHTTPDefinition(
                required_fields=["port", "hostname"],
                filters={
                    "port": FilterDefinition(
                        value=getattr(inject_content, "port", []),
                        operator=Operator.AND,
                    ),
                    **hostname_and_org_filters,
                },
            ),
            "cloud_provider_asset_discovery": ContractHTTPDefinition(
                required_fields=["cloud_provider", "hostname"],
                filters={
                    "cloud.provider": FilterDefinition(
                        value=getattr(inject_content, "cloud_provider", []),
                        operator=Operator.AND,
                    ),
                    **hostname_and_org_filters,
                },
            ),
            "custom_query": ContractHTTPDefinition(
                target_field="custom_query",
                required_fields=["custom_query"],
                filters=None,
            ),
        }

        contract_http_definition = contract_http_definitions[inject_content.contract]

        if not contract_http_definition:
            self.helper.injector_logger.error(
                f"{LOG_PREFIX} - The contract name is invalid.",
                {"contract_name": inject_content.contract},
            )
            raise InvalidContractError(f"{LOG_PREFIX} - The contract name is invalid.")

        return contract_http_definition

    def process_shodan_search(
        self, normalize_input_data: NormalizeInputData
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """The main process that triggers the Shodan search.

        It begins by retrieving all the information provided by the user (inject_content and targets), then retrieves
        the definition of the corresponding contract, executes the Shodan search for these targets, and finally
        retrieves the user's quota information.

        Args:
            normalize_input_data (NormalizeInputData): Object containing all information about the content injected by
                the user and/or the targets.

        Returns:
            tuple[dict[str, Any], dict[str, Any]]:
                - The first dictionary (results) contains the results of the Shodan search, structured by target.
                - The second dictionary (shodan_credit_user) contains the user information (quota) retrieved from Shodan.

        Raises:
            MissingRequiredFieldError: Raised when a required field is missing in the input data.
            InvalidContractError: Raised when a provided contract ID or name is invalid.
            InvalidTargetPropertySelectorError: Raised when the target property selector is unsupported or invalid.
            InvalidTargetFieldError: Raised when a target field is unsupported or invalid.
            NoTargetsRecovered: Raised when no targets could be resolved from input data.
        """

        self.helper.injector_logger.info(
            f"{LOG_PREFIX} - Starting the Shodan search process...",
        )
        inject_content = normalize_input_data.inject_content
        targets = normalize_input_data.targets

        contract_http_definition = self._get_contract_http_definition(inject_content)
        results = self._execute_contract(
            inject_content, targets, contract_http_definition
        )

        shodan_credit_user = self._get_user_info()

        self.helper.injector_logger.info(
            f"{LOG_PREFIX} - Finalization of the Shodan search process.",
        )
        return results, shodan_credit_user
