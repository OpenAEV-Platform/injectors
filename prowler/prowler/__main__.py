"""Main entry point for the Prowler injector."""

import logging
import sys
from pathlib import Path

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
        # Load the injector icon for the helper
        icon_bytes = (
            Path(__file__).parents[1] / str(config.injector.icon_filepath)
        ).read_bytes()
        helper = OpenAEVInjectorHelper(
            config=OpenAEVConfigHelper.from_configuration_object(
                config.to_daemon_config()
            ),
            icon=icon_bytes,
        )
        ProwlerInjector(config=config, helper=helper).start()
    except ValidationError:
        logger.error("%s Configuration error", LOG_PREFIX)
        sys.exit(2)
    except KeyboardInterrupt:
        logger.info("%s Injector stopped by user", LOG_PREFIX)
    except Exception:
        logger.error("%s Fatal startup error", LOG_PREFIX)
        sys.exit(1)


if __name__ == "__main__":
    main()
