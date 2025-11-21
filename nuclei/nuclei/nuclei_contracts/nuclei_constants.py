from pyoaev.security_domain.types import SecurityDomains

# -- CONTRACT --
TYPE = "openaev_nuclei"
CLOUD_SCAN_CONTRACT = "c01fa03a-ea7e-43a3-9b1a-44b2f41a8c5f"
MISCONFIG_SCAN_CONTRACT = "a4eb02bd-3c9f-4a97-b9a1-54a9b7a7f21e"
EXPOSURE_SCAN_CONTRACT = "9c4b2f29-61f6-4ae3-80e7-928fe4a2fc0b"
PANEL_SCAN_CONTRACT = "3cf1b7a6-39d2-4531-8c8e-2b7c67470d1e"
XSS_SCAN_CONTRACT = "2e7fc079-9ebf-4adf-8d94-79d8f7bb32f4"
WORDPRESS_SCAN_CONTRACT = "2e7fc079-4531-4444-4444-44b2f41a8c5f"
HTTP_SCAN_CONTRACT = "2e7fc079-4444-4531-4444-2b7c67470d1e"
TEMPLATE_SCAN_CONTRACT = "2e7fc079-4531-4444-4444-928fe4a2fc0b"
CVE_SCAN_CONTRACT = "2e7fc079-4444-4531-4444-928fe4a1fc0b"
CONTRACT_LABELS = {
    CLOUD_SCAN_CONTRACT: ("Cloud Templates", "Cloud Templates", [SecurityDomains.NETWORK.value, SecurityDomains.CLOUD.value]),
    MISCONFIG_SCAN_CONTRACT: ("Misconfigurations", "Mauvaises configurations", [SecurityDomains.NETWORK.value, SecurityDomains.WEB_APP.value]),
    EXPOSURE_SCAN_CONTRACT: ("Exposures", "Expositions", [SecurityDomains.NETWORK.value, SecurityDomains.WEB_APP.value]),
    CVE_SCAN_CONTRACT: ("CVE Scan", "Scan CVE", [SecurityDomains.NETWORK.value]),
    PANEL_SCAN_CONTRACT: ("Panel Scan", "Scan Panel", [SecurityDomains.NETWORK.value, SecurityDomains.WEB_APP.value]),
    XSS_SCAN_CONTRACT: ("XSS Scan", "Scan XSS", [SecurityDomains.NETWORK.value, SecurityDomains.WEB_APP.value]),
    WORDPRESS_SCAN_CONTRACT: ("Wordpress Scan", "Scan Wordpress", [SecurityDomains.NETWORK.value, SecurityDomains.WEB_APP.value]),
    TEMPLATE_SCAN_CONTRACT: ("TEMPLATES Scan", "Scan TEMPLATES", [SecurityDomains.NETWORK.value]),
}
