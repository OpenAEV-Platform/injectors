"""OpenAEV runtime boundary for the Prowler injector."""

from pyoaev.helpers import OpenAEVInjectorHelper

from prowler.models import ConfigLoader


class ProwlerInjector:
    """Register the foundation injector without assessment contracts."""

    def __init__(self, config: ConfigLoader, helper: OpenAEVInjectorHelper) -> None:
        """Initialize the injector with its configuration and helper."""
        self.config = config
        self.helper = helper

    def start(self) -> None:
        """Start the injector listener after zero-contract registration."""
        self.config.to_daemon_config()
        self.helper.listen(message_callback=self.process_message)

    def process_message(self, _data: dict[str, object]) -> None:
        """Reject execution because CHK.001 registers no contracts."""
        raise RuntimeError("Prowler assessment contracts are not registered")
