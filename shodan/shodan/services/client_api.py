import re
from dataclasses import dataclass
from enum import Enum
from urllib.parse import quote_plus, urljoin

import requests
from limiter import Limiter
from pyoaev.helpers import OpenAEVInjectorHelper
from tenacity import RetryError, retry, stop_after_attempt, wait_exponential_jitter

from shodan.contracts import ShodanContractId
from shodan.models import ConfigLoader

LOG_PREFIX = "[SHODAN_CLIENT_API]"


class MissingRequiredFieldError(ValueError):
    pass


@dataclass
class ShodanRestAPIDefinition:
    http_method: str
    endpoint: str
    path_parameter: bool = False


class ShodanRestAPI(Enum):
    SEARCH_SHODAN = ShodanRestAPIDefinition(
        http_method="GET",
        endpoint="shodan/host/search",
    )
    HOST_INFORMATION = ShodanRestAPIDefinition(
        http_method="GET",
        path_parameter=True,
        endpoint="shodan/host/{target}",
    )
    API_PLAN_INFORMATION = ShodanRestAPIDefinition(
        http_method="GET", endpoint="api-info"
    )

    @property
    def http_method(self) -> str:
        return self.value.http_method

    @property
    def endpoint(self) -> str:
        return self.value.endpoint


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
    def _split_target(raw_input: str) -> list[str]:
        return [target for target in re.split(r"[,\s]+", raw_input or "") if target]

    @staticmethod
    def _secure_url(url: str) -> str:
        if not url:
            return url
        if "?query" in url:
            return url.split("&key=")[0]
        return url.split("?key=")[0]

    @staticmethod
    def _build_query(query_params: dict[str, tuple[str, str]]) -> str:
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
        url = urljoin(self.base_url, endpoint)
        api_key = f"key={self.api_key.get_secret_value()}"
        if not query_params and "?query=" not in url:
            return f"{url}?{api_key}"
        if is_custom_query and "?query=" in url:
            return f"{url}&{api_key}"
        return f"{url}?{query_params}&{api_key}"

    # SECTION INFO
    def _get_user_info(self):
        self.helper.injector_logger.info(
            f"{LOG_PREFIX} - Preparation for user quota recovery...",
        )

        return self._process_request(
            raw_input="user_info",
            request_api=ShodanRestAPI.API_PLAN_INFORMATION,
        )

    # CONTRACT - CVE ENUMERATION
    def _get_cve_enumeration(self, inject_content):
        hostname = inject_content.get("hostname")
        if not hostname:
            raise MissingRequiredFieldError(
                f"{LOG_PREFIX} - The 'Hostname' field is required and cannot be empty."
            )

        filters = {
            "has_vuln": ("true", "and"),
            "hostname": ("{target},*.{target}", "or"),
            "org": (inject_content.get("organization") or "{target}", "end"),
        }
        return self._process_request(
            raw_input=hostname,
            request_api=ShodanRestAPI.SEARCH_SHODAN,
            filters_template=filters,
        )

    # CONTRACT - CVE SPECIFIC WATCHLIST
    def _get_cve_specific_watchlist(self, inject_content):
        hostname = inject_content.get("hostname")
        if not hostname:
            raise MissingRequiredFieldError(
                f"{LOG_PREFIX} - The 'Hostname' field is required and cannot be empty."
            )

        filters = {
            "vuln": (inject_content.get("vulnerability"), "and"),
            "hostname": ("{target},*.{target}", "and"),
            "org": (inject_content.get("organization") or "{target}", "end"),
        }
        return self._process_request(
            raw_input=hostname,
            request_api=ShodanRestAPI.SEARCH_SHODAN,
            filters_template=filters,
        )

    # CONTRACT - CLOUD PROVIDER ASSET DISCOVERY
    def _get_cloud_provider_asset_discovery(self, inject_content):
        hostname = inject_content.get("hostname")
        if not hostname:
            raise MissingRequiredFieldError(
                f"{LOG_PREFIX} - The 'Hostname' field is required and cannot be empty."
            )

        cloud_provider = inject_content.get("cloud_provider")
        # Please note that the default values are by nature a list.
        if isinstance(cloud_provider, list):
            cloud_provider = ",".join(cloud_provider)

        filters = {
            "cloud.provider": (cloud_provider, "and"),
            "hostname": ("{target},*.{target}", "or"),
            "org": (inject_content.get("organization") or "{target}", "end"),
        }
        return self._process_request(
            raw_input=hostname,
            request_api=ShodanRestAPI.SEARCH_SHODAN,
            filters_template=filters,
        )

    # CONTRACT - CRITICAL PORTS AND EXPOSED ADMIN INTERFACE
    def _get_critical_ports_and_exposed_admin_interface(self, inject_content):
        hostname = inject_content.get("hostname")
        if not hostname:
            raise MissingRequiredFieldError(
                f"{LOG_PREFIX} - The 'Hostname' field is required and cannot be empty."
            )

        port = inject_content.get("port")
        # Please note that the default values are by nature a list.
        if isinstance(port, list):
            port = ",".join(port)

        filters = {
            "port": (port, "and"),
            "hostname": ("{target},*.{target}", "or"),
            "org": (inject_content.get("organization") or "{target}", "end"),
        }
        return self._process_request(
            raw_input=hostname,
            request_api=ShodanRestAPI.SEARCH_SHODAN,
            filters_template=filters,
        )

    # CONTRACT - CUSTOM QUERY
    def _get_custom_query(self, inject_content):
        custom_query = inject_content.get("custom_query")
        http_method = inject_content.get("http_method")
        if not custom_query:
            raise MissingRequiredFieldError(
                f"{LOG_PREFIX} - The 'Custom Query' field is required and cannot be empty."
            )

        return self._process_request(
            raw_input=custom_query,
            request_api=None,
            filters_template=None,
            is_custom_query=True,
            http_method_custom_query=http_method,
        )

    # CONTRACT - DOMAIN DISCOVERY
    def _get_domain_discovery(self, inject_content):
        hostname = inject_content.get("hostname")
        if not hostname:
            raise MissingRequiredFieldError(
                f"{LOG_PREFIX} - The 'hostname' field is required and cannot be empty."
            )

        filters = {
            "hostname": ("{target},*.{target}", "or"),
            "org": (inject_content.get("organization") or "{target}", "end"),
        }
        return self._process_request(
            raw_input=hostname,
            request_api=ShodanRestAPI.SEARCH_SHODAN,
            filters_template=filters,
        )

    # CONTRACT - HOST ENUMERATION
    def _get_host_enumeration(self, inject_content):
        host = inject_content.get("host")
        if not host:
            raise MissingRequiredFieldError(
                f"{LOG_PREFIX} - The 'host' field is required and cannot be empty."
            )
        return self._process_request(
            raw_input=host,
            request_api=ShodanRestAPI.HOST_INFORMATION,
        )

    def _process_request(
        self,
        raw_input: str,
        request_api: ShodanRestAPI | None,
        filters_template: dict = None,
        is_custom_query: bool = False,
        http_method_custom_query: str | None = None,
    ):

        if is_custom_query:
            targets = [raw_input]
            http_method = http_method_custom_query
            endpoint_template = raw_input
            path_parameter = None
        else:
            targets = self._split_target(raw_input)
            http_method = request_api.value.http_method
            endpoint_template = request_api.value.endpoint
            path_parameter = request_api.value.path_parameter

        results = []
        for target in targets:
            new_endpoint = endpoint_template
            query_params = None
            encoded_for_shodan = None
            if path_parameter:
                new_endpoint = endpoint_template.format(target=target)

            if filters_template:
                filters = {}
                for key, (target_value, operator) in filters_template.items():
                    filters[key] = (target_value.format(target=target), operator)

                query_params = self._build_query(filters)
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
        return {"targets": targets, "data": results}

    def _request_data(self, method: str, url: str):
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

    def process_shodan_search(
        self, contract_id: ShodanContractId, inject_content: dict
    ):
        self.helper.injector_logger.info(
            f"{LOG_PREFIX} - Starting the Shodan search process...",
        )
        contract_handler = {
            ShodanContractId.CVE_ENUMERATION: self._get_cve_enumeration,
            ShodanContractId.CVE_SPECIFIC_WATCHLIST: self._get_cve_specific_watchlist,
            ShodanContractId.CLOUD_PROVIDER_ASSET_DISCOVERY: self._get_cloud_provider_asset_discovery,
            ShodanContractId.CRITICAL_PORTS_AND_EXPOSED_ADMIN_INTERFACE: self._get_critical_ports_and_exposed_admin_interface,
            ShodanContractId.CUSTOM_QUERY: self._get_custom_query,
            ShodanContractId.DOMAIN_DISCOVERY: self._get_domain_discovery,
            ShodanContractId.HOST_ENUMERATION: self._get_host_enumeration,
        }

        contract = contract_handler.get(contract_id)
        if not contract:
            raise ValueError(
                f"{LOG_PREFIX} - The contract ID is invalid.",
                {"contract_id": contract_id},
            )

        results = contract(inject_content)
        shodan_credit_user = self._get_user_info()

        self.helper.injector_logger.info(
            f"{LOG_PREFIX} - Finalization of the Shodan search process.",
        )
        return results, shodan_credit_user
