import json
import sched
import subprocess
import time
import uuid
from multiprocessing import Process

import requests
from pyoaev.apis.inputs.search import (
    Filter,
    FilterGroup,
    InjectorContractSearchPaginationInput,
)
from pyoaev.client import OpenBAS
from pyoaev.contracts.contract_config import ContractText
from pyoaev.utils import setup_logging_config

from nuclei.helpers.nuclei_process import NucleiProcess
from nuclei.nuclei_contracts.nuclei_contracts import NucleiContracts


class ExternalContractsScheduler:
    def __init__(self, api_client: OpenBAS, injector_id: str, period: int, logger):
        self.scheduler = sched.scheduler(time.time, time.sleep)
        self.manager = ExternalContractsManager(api_client, injector_id, logger)
        self._period = period

    def start(self):
        self.scheduler.enter(
            delay=0,
            priority=1,
            action=self.__schedule,
            argument=(self.scheduler, self.manager.spawn_process, self._period),
        )
        self.scheduler.run()

    def __schedule(self, scheduler, callback, delay):
        callback()
        scheduler.enter(
            delay=delay,
            priority=1,
            action=self.__schedule,
            argument=(scheduler, callback, delay),
        )


class ExternalContractsManager:
    def __init__(self, api_client: OpenBAS, injector_id: str, logger):
        self._api_client = api_client
        self._injector_id = injector_id
        self._logger = logger

    def spawn_process(self):
        process = Process(target=self.manage_contracts)
        process.start()
        process.join()

    def manage_contracts(self):
        # unfortunately, need to reenable module-level configs in spawned process
        setup_logging_config(self._logger.log_level, self._logger.json_logging)

        self._logger.info("Start maintaining external contracts in the background...")
        self._update_templates()
        cve_templates_metadata = self.fetch_nuclei_cve_templates_list()
        current_contracts = self.fetch_all_current_contracts()

        template_to_create_contract = []
        template_to_update_contract = {}
        for template in cve_templates_metadata:
            found = False
            for contract in current_contracts:
                if contract[
                    "injector_contract_external_id"
                ] == self.theoretical_external_id(template):
                    current_contracts.remove(contract)
                    template_to_update_contract[
                        contract["injector_contract_external_id"]
                    ] = self.make_contract_update(
                        contract["injector_contract_id"], template
                    )
                    found = True
                    break
            if not found:
                template_to_create_contract.append(
                    self.make_contract_create(str(uuid.uuid4()), template)
                )
        contracts_to_delete = current_contracts

        for contract in template_to_create_contract:
            try:
                self._logger.info(
                    "Creating external contract: {}".format(
                        contract["external_contract_id"]
                    )
                )
                self._api_client.injector_contract.create(contract)
            except Exception as e:
                self._logger.error(e)
                continue

        for key, contract in template_to_update_contract.items():
            try:
                self._logger.info("Updating external contract: {}".format(key))
                self._api_client.injector_contract.update(key, contract)
            except Exception as e:
                self._logger.error(e)
                continue

        for contract in contracts_to_delete:
            try:
                self._logger.info(
                    "Deleting external contract: {}".format(
                        contract["injector_contract_external_id"]
                    )
                )
                self._api_client.injector_contract.delete(
                    contract["injector_contract_external_id"]
                )
            except Exception as e:
                self._logger.error(e)
                continue

        self._logger.info("Done maintaining external contracts in the background.")

    def make_contract_create(self, contract_id, template):
        return self._make_contract(contract_id, template).to_contract_add_input(
            self._injector_id
        )

    def make_contract_update(self, contract_id, template):
        return self._make_contract(contract_id, template).to_contract_update_input()

    def _make_contract(self, contract_id: str, template):
        config = NucleiContracts.base_contract_config()
        fields = NucleiContracts.core_contract_fields() + [
            ContractText(
                key="template",
                label="Manual template path (-t)",
                mandatory=False,
                defaultValue=[template["file_path"]],
            )
        ]
        outputs = NucleiContracts.core_outputs()
        contract = NucleiContracts.build_contract(
            contract_id,
            self.theoretical_external_id(template),
            config,
            fields,
            outputs,
            template["ID"],
            template["ID"],
        )
        contract.add_vulnerability(template["ID"])
        return contract

    def external_id_prefix(self):
        return "external-injector-contract_{}".format(self._injector_id)

    def theoretical_external_id(self, cve_template_metadata):
        return "{}_{}".format(self.external_id_prefix(), cve_template_metadata["ID"])

    def fetch_nuclei_cve_templates_list(self):
        response = requests.Session().get(
            "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/refs/heads/main/cves.json"
        )
        response.raise_for_status()
        # response is not json, but a file with one serialised json object per line
        return [json.loads(line) for line in response.iter_lines()]

    def fetch_all_current_contracts(self):
        contracts = []

        current_page = 0
        last = False

        while not last:
            page = self.get_page_of_contracts(page_number=current_page)
            contracts.extend(
                [
                    contract
                    for contract in page["content"]
                    # filter out any contract not found to have been created by this process
                    # we could not do this via API since injector_contract_external_id should
                    # not be exposed as a filter
                    if str(contract["injector_contract_external_id"]).startswith(
                        self.external_id_prefix()
                    )
                ]
            )
            last = page["last"]
            current_page += 1

        return contracts

    def get_page_of_contracts(self, page_number=0):
        search_input = InjectorContractSearchPaginationInput(
            page_number,
            20,
            FilterGroup(
                "and",
                [
                    Filter(
                        "injector_contract_injector", "and", "eq", [self._injector_id]
                    ),
                ],
            ),
            include_full_details=False,
        )

        return self._api_client.injector_contract.search(search_input)

    def _update_templates(self):
        self._logger.info("Updating templates...")
        try:
            NucleiProcess.nuclei_update_templates()
            self._logger.info("Templates updated successfully.")
        except subprocess.CalledProcessError as e:
            self._logger.error(f"Template update failed: {e}")
