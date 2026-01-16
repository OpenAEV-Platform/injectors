from dataclasses import dataclass
from typing import Dict

import requests


@dataclass
class ExecutionResult:
    url: str
    status_code: int
    success: bool
    message: str

    @staticmethod
    def from_http_response(response):
        success = 200 <= response.status_code < 300

        message = (
            "Teams notification sent successfully"
            if success
            else f"Teams notification failed (HTTP {response.status_code})"
        )

        return ExecutionResult(
            url=response.url,
            status_code=response.status_code,
            success=success,
            message=message,
        )


class TeamsClient:

    @staticmethod
    def post_message(url: str, payload: Dict) -> ExecutionResult:
        response = requests.post(url=url, json=payload)
        return ExecutionResult.from_http_response(response)
