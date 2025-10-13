from typing import Any, Dict, List

from common.common.constants import ASSET_GROUPS_KEY_RABBITMQ
from pyoaev.apis.inputs.search import Filter, FilterGroup, SearchPaginationInput


class Pagination:

    @staticmethod
    def get_page_of_endpoint_targets(
        helper,
        asset_group_ids: List[str],
        page_number: int = 0,
        page_size: int = 20,
    ) -> Dict[str, Any]:
        search_input = SearchPaginationInput(
            page_number,
            page_size,
            FilterGroup(
                "or", [Filter(ASSET_GROUPS_KEY_RABBITMQ, "or", "contains", asset_group_ids)]
            ),
            None,
            None,
        )
        return helper.api.endpoint.searchTargets(search_input)

    @staticmethod
    def fetch_all_targets(
        helper,
        asset_group_ids: List[str],
    ) -> List[Dict[str, Any]]:
        targets = []
        current_page = 0
        last = False
        asset_group_ids: List[str]
        while not last:
            page = Pagination.get_page_of_endpoint_targets(
                helper, asset_group_ids, page_number=current_page
            )
            targets.extend(page["content"])
            last = page["last"]
            current_page += 1

        return targets
