from dataclasses import dataclass
from enum import Enum
from typing import Union

from pydantic import BaseModel, Field


@dataclass
class ShodanRestAPIDefinition:
    http_method: str
    endpoint: str


class ShodanRestAPI(Enum):
    SEARCH_SHODAN = ShodanRestAPIDefinition(
        http_method="GET",
        endpoint="shodan/host/search",
    )
    API_PLAN_INFORMATION = ShodanRestAPIDefinition(
        http_method="GET",
        endpoint="api-info",
    )

    @property
    def http_method(self) -> str:
        return self.value.http_method

    @property
    def endpoint(self) -> str:
        return self.value.endpoint


class Operator(str, Enum):
    AND = "and"
    OR = "or"


class FilterDefinition(BaseModel):
    value: Union[str, list[str]]
    operator: Operator | None = Field(default=None)


class ContractHTTPDefinition(BaseModel):
    target_field: str = Field(default="hostname")
    required_fields: list[str]
    filters: dict[str, FilterDefinition] | None = Field(default=None)
