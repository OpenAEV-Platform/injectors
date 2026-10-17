from pyoaev.security_domain.types import SecurityDomains

# -- CONTRACT --
TYPE = "openaev_strix"

# Autonomous assessment of authorized network / web / API targets resolved from
# OpenAEV assets or entered manually.
NETWORK_ASSESSMENT_CONTRACT = "b7f1d2a4-1c3e-4f6a-9b2d-5e8c7a0f1234"
# Autonomous assessment of a code target (git repository URL or local path
# mounted into the Strix sandbox).
CODE_ASSESSMENT_CONTRACT = "c9a2e3b5-2d4f-5a7b-8c1e-6f9d0b1a2345"

CONTRACT_LABELS = {
    NETWORK_ASSESSMENT_CONTRACT: (
        "Autonomous Assessment (Network / Web / API)",
        "Évaluation autonome (Réseau / Web / API)",
        [
            SecurityDomains.NETWORK.value,
            SecurityDomains.WEB_APP.value,
            SecurityDomains.CLOUD.value,
        ],
    ),
    CODE_ASSESSMENT_CONTRACT: (
        "Autonomous Assessment (Code repository)",
        "Évaluation autonome (Dépôt de code)",
        [SecurityDomains.WEB_APP.value],
    ),
}
