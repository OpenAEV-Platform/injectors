import json
import time

import jc
from pyoaev.helpers import OpenAEVConfigHelper, OpenAEVInjectorHelper
from pyoaev.signatures import SignatureManager
from pyoaev.signatures.models import build_network_configs

from injector_common.constants import TARGET_PROPERTY_SELECTOR_KEY, TARGET_SELECTOR_KEY
from injector_common.dump_config import intercept_dump_argument
from injector_common.targets import TargetProperty, Targets
from nmap.configuration.config_loader import ConfigLoader
from nmap.helpers.nmap_command_builder import NmapCommandBuilder
from nmap.helpers.nmap_output_parser import NmapOutputParser
from nmap.helpers.nmap_process import NmapProcess


class OpenAEVNmap:
    def __init__(self):
        self.config = OpenAEVConfigHelper.from_configuration_object(
            ConfigLoader().to_daemon_config()
        )
        intercept_dump_argument(self.config.get_config_obj())
        self.helper = OpenAEVInjectorHelper(
            self.config, open("nmap/img/icon-nmap.png", "rb")
        )
        self.signature_manager = SignatureManager(self.helper.api)

        self.current_inject_id = ""
        self.current_selector_key = ""
        self.current_selector_property = ""
        self.current_assets = []
        self.current_target_results = None

    def update_current_elements(self, data: dict) -> None:
        self.current_inject_id = data["injection"]["inject_id"]

        content = data["injection"]["inject_content"]
        self.current_selector_key = content[TARGET_SELECTOR_KEY]
        self.current_selector_property = content[TARGET_PROPERTY_SELECTOR_KEY]

        self.current_assets = data.get(self.current_selector_key, [])

        self.current_target_results = Targets.extract_targets(
            self.current_selector_key, self.current_selector_property, data, self.helper
        )

    def get_targets(self) -> list:
        targets = self.current_target_results.targets
        # Handle empty targets as an error
        if not targets:
            message = f"No target identified for the property {TargetProperty[self.current_selector_property.upper()].value}"
            raise ValueError(message)

        return targets

    def build_target_meta(self) -> list[dict]:
        target_meta = []

        for asset in self.current_assets:
            asset_meta = {key: None for key in ["agent", "asset", "asset_group"]}
            if asset_id := asset.get("asset_id"):
                asset_meta["asset"] = asset_id
            if asset_group_id := asset.get("asset_group_id"):
                asset_meta["asset_group"] = asset_group_id
            if asset_agents := asset.get("asset_agents"):
                agents_id = list(
                    set(
                        agent["agent_id"]
                        for agent in asset_agents
                        if agent.get("agent_id")
                    )
                )
                # logger warning if more than 1?
                if agents_id:
                    asset_meta["agent"] = agents_id[0]
            target_meta.append(asset_meta)

        return target_meta

    def nmap_execution(self, start: float, data: dict, targets: list) -> dict:
        contract_id = data["injection"]["inject_injector_contract"]["convertedContent"][
            "contract_id"
        ]
        # Build Arguments to execute
        nmap_args = NmapCommandBuilder.build_args(contract_id, targets)

        self.helper.injector_logger.info(
            "Executing nmap with command: " + " ".join(nmap_args)
        )

        message = Targets.build_execution_message(
            selector_key=self.current_selector_key,
            data=data,
            command_args=nmap_args,
        )

        callback_data = {
            "execution_message": message,
            "execution_status": "INFO",
            "execution_duration": int(time.time() - start),
            "execution_action": "command_execution",
        }

        self.helper.api.inject.execution_callback(
            inject_id=self.current_inject_id,
            data=callback_data,
        )

        nmap_result = NmapProcess.nmap_execute(nmap_args)
        result = jc.parse("xml", nmap_result)

        return NmapOutputParser.parse(data, result, self.current_target_results)

    def process_message(self, data: dict) -> None:
        start = time.time()
        # Notify API of reception and expected number of operations
        reception_data = {"tracking_total_count": 1}

        # setting the current
        self.update_current_elements(data)

        targets = self.get_targets()

        network_injector_config = build_network_configs(targets)
        pre = self.signature_manager.compile_pre_execution_signatures(
            network_injector_config
        )

        self.helper.api.inject.execution_reception(
            inject_id=self.current_inject_id, data=reception_data
        )
        # Execute inject
        try:
            execution_result = self.nmap_execution(start, data, targets)
            execution_message = execution_result["message"]
            execution_status = "SUCCESS"
        except Exception as err:
            execution_result = None
            execution_message = str(err)
            execution_status = "ERROR"

        callback_data = {
            "execution_message": execution_message,
            "execution_status": execution_status,
            "execution_action": "complete",
        }
        if execution_result:
            callback_data["execution_output_structured"] = json.dumps(
                execution_result["outputs"]
            )

        tool_output = {
            "status": {"SUCCESS": "success", "ERROR": "failed"}[execution_status]
        }
        post = self.signature_manager.compile_post_execution_signatures(
            pre, tool_output
        )

        post["ports_discovered"] = []
        post["services_discovered"] = []
        if execution_result:
            outputs = execution_result.get("outputs", {})
            post["ports_discovered"] = outputs.get("ports", [])
            post["services_discovered"] = outputs.get("scan_results", [])

        target_meta = self.build_target_meta()

        callback_data["execution_duration"] = int(time.time() - start)
        self.helper.api.inject.execution_callback(
            inject_id=self.current_inject_id, data=callback_data
        )

        for expectation_type in ["DETECTION", "PREVENTION"]:
            payload = self.signature_manager.build_payload(
                post, target_meta, expectation_type=expectation_type
            )
            self.signature_manager.send_signatures(
                inject_id=self.current_inject_id,
                phase="execution_complete",
                signatures=payload,
            )

    # Start the main loop
    def start(self):
        self.helper.listen(message_callback=self.process_message)


if __name__ == "__main__":
    openAEVNmap = OpenAEVNmap()
    openAEVNmap.start()
