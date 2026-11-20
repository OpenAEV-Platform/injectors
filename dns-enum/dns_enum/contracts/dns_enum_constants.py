# -- CONTRACT --
TYPE = "openaev_dns_enum"
DNS_ENUMERATION_CONTRACT = "5b0f9d62-7a1c-4e3b-9f84-2d6c1a7e9b30"

# -- CONTRACT FIELD KEYS --
DOMAINS_KEY = "domains"
PASSIVE_SOURCES_KEY = "passive_sources"
RECORD_TYPES_KEY = "record_types"
BRUTE_FORCE_KEY = "brute_force"
WORDLIST_KEY = "wordlist"
RATE_LIMIT_KEY = "rate_limit"
TIMEOUT_KEY = "timeout"
CREATE_ENDPOINTS_KEY = "create_endpoints"
ENDPOINT_TAG_KEY = "endpoint_tag"
ASSET_GROUP_ID_KEY = "asset_group_id"

# -- RECORD TYPES (dnsx flag and JSON key are the lower-case name) --
RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT"]
DEFAULT_RECORD_TYPES = ["A", "AAAA", "CNAME"]

# -- DEFAULTS AND BOUNDS --
DEFAULT_RATE_LIMIT = 100
MAX_RATE_LIMIT = 1000
DEFAULT_TIMEOUT_SECONDS = 600
MAX_TIMEOUT_SECONDS = 3600
MAX_WORDLIST_WORDS = 10000
DEFAULT_ENDPOINT_TAG = "discovered:dns"
ENDPOINT_TAG_COLOR = "#00897b"
EXTERNAL_REFERENCE_PREFIX = "dns-enum:"

# -- OUTPUT FIELDS --
DISCOVERED_HOSTS_FIELD = "discovered_hosts"
IPV4_FIELD = "ipv4"
HOSTNAMES_FIELD = "hostnames"
MANUAL_TARGETS_FIELD = "manual_targets"
ACTION_OUTPUT_FIELD = "action_output"
EXPECTATION_SIGNATURES_FIELD = "expectation_signatures"
