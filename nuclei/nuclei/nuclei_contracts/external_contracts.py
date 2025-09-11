import json
import sched
import time
import uuid
from multiprocessing import Process

import requests
from nuclei_contracts.nuclei_contracts import NucleiContracts
from pyobas.apis.inputs.search import (
    Filter,
    FilterGroup,
    InjectorContractSearchPaginationInput,
)
from pyobas.client import OpenBAS
from pyobas.contracts.contract_config import (
    Contract,
    ContractAsset,
    ContractCardinality,
    ContractConfig,
    ContractElement,
    ContractExpectations,
    ContractOutputElement,
    ContractOutputType,
    ContractSelect,
    ContractText,
    Expectation,
    ExpectationType,
    SupportedLanguage,
    prepare_contracts,
)


class ExternalContractsManager:
    def __init__(self, api_client: OpenBAS, injector_id: str):
        self.scheduler = sched.scheduler(time.time, time.sleep)
        self._api_client = api_client
        self._injector_id = injector_id

    def start(self):
        self.spawn_process()
        self.scheduler.enter(
            1, 1, self.__schedule, argument=(self.scheduler, self.spawn_process, 1)
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

    def spawn_process(self):
        process = Process(target=self.manage_contracts)
        process.start()
        process.join()

    def manage_contracts(self):
        cve_templates_metadata = self.fetch_nuclei_cve_templates_list()
        current_contracts = self.fetch_all_current_contracts()

        template_to_create_contract = []
        for template in cve_templates_metadata:
            for contract in current_contracts:
                if contract[
                    "injector_contract_external_id"
                ] == self.theoretical_external_id(template):
                    current_contracts.remove(contract)
                    cve_templates_metadata.remove(template)
                    break
            template_to_create_contract.append(self.make_contract(template))
        contracts_to_delete = current_contracts

        for contract in template_to_create_contract:
            try:
                self._api_client.injector_contract.create(contract)
            except:
                continue

        print("finished outersect")

    def make_contract(self, template):
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
            str(uuid.uuid4()),
            self.theoretical_external_id(template),
            config,
            fields,
            outputs,
            template["ID"],
            template["ID"],
        )
        contract.add_vulnerability(template["ID"])
        return contract.to_contract_add_input(self._injector_id)

    def external_id_prefix(self):
        return "external-injector-contract_{}".format(self._injector_id)

    def theoretical_external_id(self, cve_template_metadata):
        return "{}_{}".format(self.external_id_prefix(), cve_template_metadata["ID"])

    def fetch_nuclei_cve_templates_list(self):
        response = requests.Session().get(
            "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/refs/heads/main/cves.json"
        )
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
