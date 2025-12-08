import json
import time
from typing import Dict

import requests
from http_query.contracts_http import (
    HTTP_FORM_POST_CONTRACT,
    HTTP_FORM_PUT_CONTRACT,
    HTTP_GET_CONTRACT,
    HTTP_RAW_POST_CONTRACT,
    HTTP_RAW_PUT_CONTRACT,
    HttpContracts,
)
from helpers.helpers import HTTPHelpers
from pyoaev.helpers import OpenAEVConfigHelper, OpenAEVInjectorHelper


class OpenAEVHttp:
    def __init__(self):
        self.config = OpenAEVConfigHelper(
            __file__,
            {
                # API information
                "openaev_url": {"env": "OPENAEV_URL", "file_path": ["openaev", "url"]},
                "openaev_token": {
                    "env": "OPENAEV_TOKEN",
                    "file_path": ["openaev", "token"],
                },
                # Config information
                "injector_id": {"env": "INJECTOR_ID", "file_path": ["injector", "id"]},
                "injector_name": {
                    "env": "INJECTOR_NAME",
                    "file_path": ["injector", "name"],
                },
                "injector_type": {
                    "env": "INJECTOR_TYPE",
                    "file_path": ["injector", "type"],
                    "default": "openaev_http_query",
                },
                "injector_contracts": {"data": HttpContracts.build_contract()},
            },
        )
        self.helper = OpenAEVInjectorHelper(
            self.config, open("http_query/img/icon-http.png", "rb")
        )

    def attachments_to_files(self, request_data):
        documents = request_data["injection"].get("inject_documents", [])
        attachments = list(filter(lambda d: d["document_attached"] is True, documents))
        http_files = {}
        for attachment in attachments:
            response = self.helper.api.document.download(attachment["document_id"])
            if response.status_code == 200:
                http_files[attachment["document_name"]] = response.content
        return http_files

    def http_execution(self, data: Dict):
        # Build headers
        inject_headers = HTTPHelpers.parse_headers(
            data["injection"]["inject_content"].get("headers", [])
        )
        headers = {}
        for header_definition in inject_headers:
            headers[header_definition["key"]] = header_definition["value"]
        # Build http session
        session = requests.Session()
        is_basic_auth = data["injection"]["inject_content"]["basicAuth"]
        if is_basic_auth:
            user = data["injection"]["inject_content"]["basicUser"]
            password = data["injection"]["inject_content"]["basicPassword"]
            session.auth = (user, password)
        # Contract execution
        inject_contract = data["injection"]["inject_injector_contract"][
            "injector_contract_id"
        ]
        url = data["injection"]["inject_content"]["uri"]
        http_files = self.attachments_to_files(data)
        # Get
        if inject_contract == HTTP_GET_CONTRACT:
            response = session.get(url=url, headers=headers)
            return HTTPHelpers.response_parsing(response)
        # Post
        if inject_contract == HTTP_RAW_POST_CONTRACT:
            body = data["injection"]["inject_content"]["body"]
            response = session.post(
                url=url, headers=headers, data=body, files=http_files
            )
            return HTTPHelpers.response_parsing(response)
        # Put
        if inject_contract == HTTP_RAW_PUT_CONTRACT:
            body = data["injection"]["inject_content"]["body"]
            response = session.put(
                url=url, headers=headers, data=body, files=http_files
            )
            return HTTPHelpers.response_parsing(response)
        # Form Post
        if inject_contract == HTTP_FORM_POST_CONTRACT:
            body = HTTPHelpers.request_data_parts_body(data)
            response = session.post(
                url=url, headers=headers, data=body, files=http_files
            )
            return HTTPHelpers.response_parsing(response)
        # Form Put
        if inject_contract == HTTP_FORM_PUT_CONTRACT:
            body = HTTPHelpers.request_data_parts_body(data)
            response = session.put(
                url=url, headers=headers, data=body, files=http_files
            )
            return HTTPHelpers.response_parsing(response)
        # Nothing supported
        return {
            "code": 400,
            "status": "ERROR",
            "message": "Selected contract is not supported",
        }

    def process_message(self, data: Dict) -> None:
        start = time.time()
        inject_id = data["injection"]["inject_id"]
        # Notify API of reception and expected number of operations
        reception_data = {"tracking_total_count": 1}
        self.helper.api.inject.execution_reception(
            inject_id=inject_id, data=reception_data
        )
        # Execute inject
        try:
            execution_result = self.http_execution(data)
            execution_outputs = {"url": execution_result["url"]}
            callback_data = {
                "execution_message": execution_result["message"],
                "execution_output_structured": json.dumps(execution_outputs),
                "execution_status": execution_result["status"],
                "execution_duration": int(time.time() - start),
                "execution_action": "complete",
            }
            self.helper.api.inject.execution_callback(
                inject_id=inject_id, data=callback_data
            )
        except Exception as e:
            callback_data = {
                "execution_message": str(e),
                "execution_status": "ERROR",
                "execution_duration": int(time.time() - start),
                "execution_action": "complete",
            }
            self.helper.api.inject.execution_callback(
                inject_id=inject_id, data=callback_data
            )

    # Start the main loop
    def start(self):
        self.helper.listen(message_callback=self.process_message)


if __name__ == "__main__":
    openAEVHttp = OpenAEVHttp()
    openAEVHttp.start()
