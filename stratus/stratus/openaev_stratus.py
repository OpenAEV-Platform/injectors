import json
import os
import tempfile
import time
from importlib.resources import files
from typing import Dict, List, Optional, Tuple

from injector_common.data_helpers import DataHelpers
from injector_common.dump_config import intercept_dump_argument
from injector_common.stratus_executor import StratusExecutor
from pyoaev.helpers import OpenAEVConfigHelper, OpenAEVInjectorHelper

from stratus.configuration.config_loader import ConfigLoader
from stratus.contracts import (
    CUSTOM_TECHNIQUE_FIELD_KEY,
    PLATFORMS_BY_CONTRACT,
    TECHNIQUE_FIELD_KEY,
    PlatformSpec,
)

ICON_PATH = "img/icon-stratus.png"


class OpenAEVStratus:
    def __init__(self):
        self.config = OpenAEVConfigHelper.from_configuration_object(
            ConfigLoader().to_daemon_config()
        )
        intercept_dump_argument(self.config.get_config_obj())
        self.helper = OpenAEVInjectorHelper(self.config, self._load_icon())
        self.stratus = StratusExecutor(logger=self.helper.injector_logger)

    def _load_icon(self) -> bytes:
        icon_path = files("stratus").joinpath(ICON_PATH)
        with icon_path.open("rb") as icon_file:
            return icon_file.read()

    @staticmethod
    def _resolve_platform(data: Dict) -> PlatformSpec:
        contract_id = DataHelpers.get_injector_contract_id(data)
        platform = PLATFORMS_BY_CONTRACT.get(contract_id)
        if platform is None:
            raise ValueError(
                f"Unsupported contract '{contract_id}' for the Stratus injector"
            )
        return platform

    @staticmethod
    def _resolve_technique(content: Dict) -> Optional[str]:
        # Only treat the custom id as an override when it has real content;
        # a whitespace-only value must fall back to the selected technique.
        custom = content.get(CUSTOM_TECHNIQUE_FIELD_KEY)
        if custom and custom.strip():
            return custom.strip()
        selected = content.get(TECHNIQUE_FIELD_KEY)
        if isinstance(selected, list):
            selected = selected[0] if selected else None
        if isinstance(selected, str):
            selected = selected.strip()
        return selected or None

    @staticmethod
    def _build_env(
        platform: PlatformSpec, content: Dict
    ) -> Tuple[Dict[str, str], List[str]]:
        """Build the Stratus process environment for the target platform.

        Returns the environment mapping and the list of temp files created for
        materialized secrets so the caller can remove them after detonation.
        """
        env: Dict[str, str] = {}
        temp_files: List[str] = []
        for cred in platform.cred_fields:
            raw = content.get(cred.key)
            value = raw.strip() if isinstance(raw, str) else raw
            if not value:
                if cred.mandatory:
                    raise ValueError(f"'{cred.label}' is required")
                if cred.default is not None:
                    value = cred.default
                else:
                    continue

            if cred.as_file_env:
                with tempfile.NamedTemporaryFile(
                    mode="w", suffix=cred.file_suffix, delete=False
                ) as handle:
                    handle.write(value)
                    path = handle.name
                temp_files.append(path)
                if cred.file_mode is not None:
                    os.chmod(path, cred.file_mode)
                env[cred.as_file_env] = path
            else:
                for env_var in cred.env_vars:
                    env[env_var] = value
        return env, temp_files

    def process_message(self, data: Dict) -> None:
        start = time.time()
        inject_id = DataHelpers.get_inject_id(data)
        self.helper.api.inject.execution_reception(
            inject_id=inject_id, data={"tracking_total_count": 1}
        )

        temp_files: List[str] = []
        try:
            platform = self._resolve_platform(data)
            content = DataHelpers.get_content(data)
            technique_id = self._resolve_technique(content)
            if not technique_id:
                raise ValueError("No Stratus technique id provided")

            env, temp_files = self._build_env(platform, content)
            result = self.stratus.detonate(technique_id, env=env, cleanup=True)

            callback_data = {
                "execution_message": result.message,
                "execution_status": "SUCCESS" if result.success else "ERROR",
                "execution_duration": int(time.time() - start),
                "execution_action": "complete",
            }
            if result.success:
                callback_data["execution_output_structured"] = json.dumps(
                    result.outputs
                )
            self.helper.api.inject.execution_callback(
                inject_id=inject_id, data=callback_data
            )
        except Exception as e:
            self.helper.api.inject.execution_callback(
                inject_id=inject_id,
                data={
                    "execution_message": str(e),
                    "execution_status": "ERROR",
                    "execution_duration": int(time.time() - start),
                    "execution_action": "complete",
                },
            )
        finally:
            for path in temp_files:
                if os.path.exists(path):
                    os.remove(path)

    def start(self):
        self.helper.injector_logger.info("Starting Stratus Red Team injector...")
        self.helper.listen(message_callback=self.process_message)


if __name__ == "__main__":
    OpenAEVStratus().start()
