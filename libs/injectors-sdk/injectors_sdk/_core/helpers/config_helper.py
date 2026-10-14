"""Legacy configuration accessor used by injectors."""

import os
from typing import Dict

from xtm_oaev_sdk import Configuration, ConfigurationError

__all__ = ["OpenAEVConfigHelper"]


### DEPRECATED
class OpenAEVConfigHelper:
    def __init__(self, base_path, variables: Dict | None, config_obj: Configuration):
        if config_obj is not None:
            self.__config_obj = config_obj
        else:
            self.__config_obj = Configuration(
                config_hints=variables,
                config_file_path=os.path.join(
                    os.path.dirname(os.path.abspath(base_path)), "config.yml"
                ),
            )

    @staticmethod
    def from_configuration_object(config: Configuration):
        return OpenAEVConfigHelper(None, None, config)

    def get_config_obj(self) -> Configuration:
        return self.__config_obj

    def get_conf(self, variable, is_number=None, default=None, required=None):
        result = None
        try:
            result = (
                self.__config_obj.get(variable)
                if (self.__config_obj.get(variable) is not None)
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

    def to_configuration(self):
        return self.__config_obj
