from typing import Any, Dict, List

from pyoaev.apis.inputs.search import Filter, FilterGroup, SearchPaginationInput


class Pagination:

    @staticmethod
    def get_page_of_contracts(
        helper, page_number: int = 0, page_size: int = 20
    ) -> Dict[str, Any]:
        search_input = SearchPaginationInput(
            page_number,
            page_size,
            FilterGroup("or", [Filter("asset_groups", "and", "eq", ["test targets"])]),
            None,
            None,
        )
        return helper.api.endpoint.searchTargets(search_input)

    @staticmethod
    def fetch_all_targets(helper) -> List[Dict[str, Any]]:
        targets = []
        current_page = 0
        last = False

        while not last:
            page = Pagination.get_page_of_contracts(helper, page_number=current_page)
            targets.extend(page["content"])
            last = page["last"]
            current_page += 1

        return targets
