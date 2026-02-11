from dataclasses import dataclass
from typing import Dict

import requests
from requests.exceptions import RequestException, Timeout

DEFAULT_TIMEOUT = 5  # seconds


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

    @staticmethod
    def failure(url: str, message: str) -> "ExecutionResult":
        return ExecutionResult(
            url=url,
            status_code=0,
            success=False,
            message=message,
        )


class TeamsClient:

    @staticmethod
    def post_message(url: str, payload: Dict) -> ExecutionResult:
        try:
            response = requests.post(
                url=url,
                json=payload,
                timeout=DEFAULT_TIMEOUT,
            )
            return ExecutionResult.from_http_response(response)

        except Timeout:
            return ExecutionResult.failure(
                url=url,
                message="Teams notification timed out",
            )

        except RequestException as e:
            return ExecutionResult.failure(
                url=url,
                message=f"Teams notification failed: {e}",
            )
