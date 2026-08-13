"""Main entry point for the Prowler injector."""

import logging
import sys

from pydantic import ValidationError
from pyoaev.helpers import OpenAEVConfigHelper, OpenAEVInjectorHelper

from prowler.injector import ProwlerInjector
from prowler.models import ConfigLoader

LOG_PREFIX = "[PROWLER_MAIN]"


def main() -> None:
    """Load configuration and start the injector."""
    logger = logging.getLogger(__name__)
    try:
        config = ConfigLoader()
        helper = OpenAEVInjectorHelper(
            config=OpenAEVConfigHelper.from_configuration_object(
                config.to_daemon_config()
            )
        )
        ProwlerInjector(config=config, helper=helper).start()
    except ValidationError as error:
        logger.error("%s Configuration error: %s", LOG_PREFIX, error)
        sys.exit(2)
    except KeyboardInterrupt:
        logger.info("%s Injector stopped by user", LOG_PREFIX)
    except Exception as error:
        logger.exception("%s Fatal startup error: %s", LOG_PREFIX, error)
        sys.exit(1)


if __name__ == "__main__":
    main()
