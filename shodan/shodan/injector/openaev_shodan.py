from shodan.models import ConfigLoader
from pyoaev.helpers import OpenAEVInjectorHelper

LOG_PREFIX = "[INJECTOR]"

class ShodanInjector:
    def __init__(self, config: ConfigLoader, helper: OpenAEVInjectorHelper):
        """Initialize the Injector with necessary configurations"""

        # Load configuration file and connection helper
        self.config = config
        self.helper = helper

    def process_message(self, data: dict) -> None:
        self.helper.injector_logger.info(data)

    def start(self):
        self.helper.listen(message_callback=self.process_message)
