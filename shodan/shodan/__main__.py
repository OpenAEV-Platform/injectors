"""Main entry point for the injector."""

import logging
import os
import sys

from pydantic import ValidationError
from pyoaev.helpers import OpenAEVConfigHelper, OpenAEVInjectorHelper

from injector_common.dump_config import intercept_dump_argument
from shodan.injector.openaev_shodan import ShodanInjector
from shodan.models import ConfigLoader

# from shodan.injector.exception import InjectorConfigError

LOG_PREFIX = "[SHODAN_MAIN]"


def main() -> None:
    """Define the main function to run the injector."""
    logger = logging.getLogger(__name__)

    try:
        # Loading injector configuration
        config = ConfigLoader()
        intercept_dump_argument(config.to_daemon_config())

        # Instantiate the OpenAEV injector helper
        helper = OpenAEVInjectorHelper(
            config=OpenAEVConfigHelper.from_configuration_object(
                config.to_daemon_config()
            ),
            icon=open("shodan/img/icon-shodan.png", "rb"),
        )

        logger.info(
            f"{LOG_PREFIX} - Shodan injector configuration initialized successfully."
        )

        # Start the Shodan injector
        injector = ShodanInjector(config, helper)
        injector.start()

    except ValidationError as err:
        logger.error(f"{LOG_PREFIX} Configuration error: {err}")
        sys.exit(2)

    except KeyboardInterrupt:
        logger.info(f"{LOG_PREFIX} Injector stopped by user (Ctrl+C)")
        os._exit(0)

    except Exception as err:
        logger.exception(f"{LOG_PREFIX} Fatal error starting injector: {err}")
        sys.exit(1)


if __name__ == "__main__":
    main()
