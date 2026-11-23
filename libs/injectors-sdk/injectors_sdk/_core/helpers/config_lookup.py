"""Config lookup: the legacy configuration accessor of injectors."""

import os
from typing import Any

from xtm_oaev_sdk import Configuration, ConfigurationError, ConfigurationProtocol

__all__ = ["ConfigLookup"]


class ConfigLookup:
    """Implements ``ConfigLookupPort``."""

    def load(
        self, base_path: Any, variables: dict | None, config_obj: Any
    ) -> ConfigurationProtocol:
        if config_obj is not None:
            return config_obj
        else:
            return Configuration(
                config_hints=variables,
                config_file_path=os.path.join(
                    os.path.dirname(os.path.abspath(base_path)), "config.yml"
                ),
            )

    def get_conf(
        self,
        configuration: ConfigurationProtocol,
        variable: Any,
        is_number: Any = None,
        default: Any = None,
        required: Any = None,
    ) -> Any:
        result = None
        try:
            result = (
                configuration.get(variable)
                if (configuration.get(variable) is not None)
                else default
            )
        except ConfigurationError:
            result = default
        finally:
            if result is None and default is None and required:
                raise ValueError(
                    f"Could not find required key {variable} with no available default."
                )
            return result
