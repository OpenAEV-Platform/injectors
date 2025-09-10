import sched
import time
from multiprocessing import Process

from pyobas.apis.inputs.search import (
    Filter,
    FilterGroup,
    InjectorContractSearchPaginationInput,
)
from pyobas.client import OpenBAS


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
        process = Process(target=self.manage_contracts, args=(self._api_client,))
        process.start()
        process.join()

    def manage_contracts(self, api_client):
        contracts = self.fetch_all_current_contracts()
        print("final contracts", contracts)

    def fetch_all_current_contracts(self):
        contracts = []

        current_page = 0
        last = False

        while not last:
            page = self.get_page_of_contracts(page_number=current_page)
            contracts.extend(page["content"])
            last = page["last"]
            current_page += 1

        return contracts

    def get_page_of_contracts(self, page_number=0):
        search_input = InjectorContractSearchPaginationInput(
            page_number,
            20,
            FilterGroup(
                "or",
                [
                    Filter(
                        "injector_contract_injector", "and", "eq", [self._injector_id]
                    )
                ],
            ),
            include_full_details=False,
        )

        return self._api_client.injector_contract.search(search_input)
