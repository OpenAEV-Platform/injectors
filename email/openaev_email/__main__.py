"""Main entry point for the injector."""

import logging
import os
import sys
from pathlib import Path

from openaev_email.injector.openaev_email import EmailInjector
from openaev_email.models import ConfigLoader
from openaev_email.models.configs.injector_config_override import ICON_FILEPATH
from pydantic import ValidationError
from pyoaev.helpers import OpenAEVConfigHelper, OpenAEVInjectorHelper

from injector_common.dump_config import intercept_dump_argument

LOG_PREFIX = "[EMAIL_MAIN]"


def main() -> None:
    """Define the main function to run the injector."""
    logger = logging.getLogger(__name__)

    try:
        # Loading injector configuration
        config = ConfigLoader()
        intercept_dump_argument(config.to_daemon_config())

        # Load the injector icon for the helper
        icon_bytes = (Path(__file__).parents[1] / ICON_FILEPATH).read_bytes()

        # Instantiate the OpenAEV injector helper
        helper = OpenAEVInjectorHelper(
            config=OpenAEVConfigHelper.from_configuration_object(
                config.to_daemon_config()
            ),
            icon=icon_bytes,
        )

        logger.info(
            f"{LOG_PREFIX} Email injector configuration initialized successfully."
        )

        # Start the Email injector
        injector = EmailInjector(config, helper)
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
