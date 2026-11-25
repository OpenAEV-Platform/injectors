# -- CONTRACT --
TYPE = "openaev_nmap"
TCP_SYN_SCAN_CONTRACT = "0b7f3674-ac5d-4b95-b749-6665e74a211f"
TCP_CONNECT_SCAN_CONTRACT = "93d27459-68d0-43b1-ad65-eacc3cfa5cf7"
FIN_SCAN_CONTRACT = "6f4d7e18-c730-484a-bb09-c9c321820c0a"
TCP_SYN_VERSION_SCAN_CONTRACT = "c3a1f5d2-7e4b-4a8c-9f61-2d5b8e0a7c34"

# -- TUNING FIELDS (optional; empty = nmap's default) --
TIMING_KEY = "timing_template"
TIMING_DEFAULT = "default"
TIMING_TEMPLATES = ("T0", "T1", "T2", "T3", "T4", "T5")
MAX_RETRIES_KEY = "max_retries"
HOST_TIMEOUT_KEY = "host_timeout_seconds"
MAX_RTT_TIMEOUT_KEY = "max_rtt_timeout_ms"
MIN_RATE_KEY = "min_rate"
TOP_PORTS_KEY = "top_ports"
PORTS_KEY = "ports"
TUNING_KEYS = (
    TIMING_KEY,
    MAX_RETRIES_KEY,
    HOST_TIMEOUT_KEY,
    MAX_RTT_TIMEOUT_KEY,
    MIN_RATE_KEY,
    TOP_PORTS_KEY,
    PORTS_KEY,
)
