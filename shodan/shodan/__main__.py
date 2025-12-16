"""Main entry point for the injector."""

import logging
import os
import sys
from pathlib import Path
from pydantic import ValidationError
from pyoaev.helpers import OpenAEVInjectorHelper
from shodan.models import ConfigLoader
from shodan.injector.openaev_shodan import ShodanInjector
from shodan.contracts.shodan_contracts import ShodanContracts
# from shodan.injector.exception import InjectorConfigError

LOG_PREFIX = "[MAIN]"

def main() -> None:
    """Define the main function to run the injector."""
    logger = logging.getLogger(__name__)

    try:
        logger.info(f"{LOG_PREFIX} Starting Shodan Injector...")

        # Injector Config
        config = ConfigLoader()
        # config_dict = config.model_dump(mode="json")

        # Prepare Helper
        shodan_contracts = ShodanContracts().contracts
        config_helper_adpater = config.to_config_injector_helper_adapter(contracts=shodan_contracts)
        icon_bytes = Path("shodan/img/icon-shodan.png").read_bytes()

        helper = OpenAEVInjectorHelper(config=config_helper_adpater, icon=icon_bytes)

        logger.info(  # type: ignore[has-type]
            f"{LOG_PREFIX} The initialization of the Shodan injector configuration was successful."
        )

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