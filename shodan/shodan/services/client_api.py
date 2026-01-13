from aiohttp import ClientSession
from limiter import Limiter
from tenacity import retry, stop_after_attempt, wait_exponential_jitter

from urllib.parse import urljoin, urlencode
from shodan.contracts import ShodanContractId
from shodan.models import ConfigLoader
from pyoaev.helpers import OpenAEVInjectorHelper
LOG_PREFIX = "[SHODAN_CLIENT_API]"

class ShodanClientAPI:
    def __init__(self, config: ConfigLoader, helper: OpenAEVInjectorHelper):
        """Initialize the Injector with necessary configurations"""

        # Load configuration file and connection helper
        self.config = config
        self.helper = helper

        self.base_url = self.config.shodan.base_url
        self.api_key = self.config.shodan.api_key

        # self.api_retry = self.config.shodan.api_retry
        # self.api_backoff = self.config.shodan.api_backoff.total_seconds()
        #
        # # Limiter config
        # self.rate_limiter = Limiter(
        #     rate=self.config.shodan.api_leaky_bucket_rate,
        #     capacity=self.config.shodan.api_leaky_bucket_capacity,
        #     bucket="shodan",
        # )

        # Define headers in session and update when needed
        self.headers = {
            "key": self.api_key.get_secret_value(),
            "Content-Type": "application/json",
        }

    def _build_url(self, endpoint: str, params: dict | None = None) -> str:
        url = urljoin(self.base_url, endpoint)

        if not params:
            return url

        full_url = f"{url}?{urlencode(params)}"
        return full_url

    def _get_user_info(self):
        pass

    async def _request_data(self, url_built):
        @retry(
            stop=stop_after_attempt(max_attempt_number=self.api_retry),
            wait=wait_exponential_jitter(
                initial=1, max=self.api_backoff, exp_base=2, jitter=1
            ),
        )
        async def _retry_wrapped():
            async with ClientSession(
                    headers=self.headers,
                    raise_for_status=True,
                    trust_env=True,
            ) as session:
                async with session.get(url=url_built) as response:
                    return await response.json()

        async with self.rate_limiter:
            return await _retry_wrapped()


    def _get_host_enumeration(self, inject_content):

        ip = inject_content.get("host")
        endpoint = f"shodan/host/{ip}"

        url_built = self._build_url(endpoint)
        return self._request_data(url_built)


    def get_shodan_search(self, contract_name, inject_content):
        # Parameters available -> query / facets (optional) / page (optional) / minify (optional)
        # https://api.shodan.io/shodan/host/search?key={YOUR_API_KEY}&query={query}&facets={facets}

        contract_handler = {
            ShodanContractId.CVE_ENUMERATION: self._get_cve_enumeration,
            ShodanContractId.CVE_SPECIFIC_WATCHLIST: self._get_cve_specific_watchlist,
            ShodanContractId.CLOUD_PROVIDER_ASSET_DISCOVERY: self._get_cloud_provider_asset_discovery,
            ShodanContractId.CRITICAL_PORTS_AND_EXPOSED_ADMIN_INTERFACE: self._get_critical_ports_and_exposed_admin_interface,
            ShodanContractId.CUSTOM_QUERY: self._get_custom_query,
            ShodanContractId.DOMAIN_DISCOVERY: self._get_domain_discovery,
            ShodanContractId.HOST_ENUMERATION: self._get_host_enumeration,
        }

        shodan_credit_user = self._get_user_info()

        return []

