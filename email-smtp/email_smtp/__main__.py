"""Main entry point for the injector."""

import logging
import os
import sys
from pathlib import Path

from email_smtp.injector.openaev_email_smtp import EmailSmtpInjector
from email_smtp.models import ConfigLoader
from pydantic import ValidationError
from pyoaev.helpers import OpenAEVConfigHelper, OpenAEVInjectorHelper

from injector_common.dump_config import intercept_dump_argument

LOG_PREFIX = "[EMAIL_SMTP_MAIN]"


def main() -> None:
    """Define the main function to run the injector."""
    logger = logging.getLogger(__name__)

    try:
        # Loading injector configuration
        config = ConfigLoader()
        intercept_dump_argument(config.to_daemon_config())

        # Load the injector icon for the helper
        icon_path = config.injector.icon_filepath
        icon_bytes = (
            (Path(__file__).parents[1] / icon_path).read_bytes() if icon_path else None
        )

        # Instantiate the OpenAEV injector helper
        helper = OpenAEVInjectorHelper(
            config=OpenAEVConfigHelper.from_configuration_object(
                config.to_daemon_config()
            ),
            icon=icon_bytes,
        )

        logger.info(
            f"{LOG_PREFIX} Email (SMTP) injector configuration initialized successfully."
        )

        # Start the Email (SMTP) injector
        injector = EmailSmtpInjector(config, helper)
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
