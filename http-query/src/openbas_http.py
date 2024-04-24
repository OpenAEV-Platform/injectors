import time
from typing import Dict

import requests
from contracts_http import (
    HTTP_FORM_POST_CONTRACT,
    HTTP_FORM_PUT_CONTRACT,
    HTTP_GET_CONTRACT,
    HTTP_RAW_POST_CONTRACT,
    HTTP_RAW_PUT_CONTRACT,
    HttpContracts,
)
from pyobas.helpers import OpenBASConfigHelper, OpenBASInjectorHelper


class OpenBASHttp:
    def __init__(self):
        self.config = OpenBASConfigHelper(
            __file__,
            {
                # API information
                "openbas_url": {"env": "OPENBAS_URL", "file_path": ["openbas", "url"]},
                "openbas_token": {
                    "env": "OPENBAS_TOKEN",
                    "file_path": ["openbas", "token"],
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
                },
                "injector_contracts": {"data": HttpContracts.build_contract()},
            },
        )
        self.helper = OpenBASInjectorHelper(
            self.config, open("img/icon-http.png", "rb")
        )

    @staticmethod
    def _request_data_parts_body(request_data):
        parts = request_data["injection"]["inject_content"]["parts"]
        keys = list(map(lambda p: p["key"], parts))
        values = list(map(lambda p: p["value"], parts))
        return dict(zip(keys, values))

    @staticmethod
    def _response_parsing(response):
        success = 200 <= response.status_code < 300
        success_status = "SUCCESS" if success else "ERROR"
        return {
            "code": response.status_code,
            "status": success_status,
            "message": response.text,
        }

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
        inject_headers = data["injection"]["inject_content"].get("headers", [])
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
        inject_contract = data["injection"]["inject_contract"]
        url = data["injection"]["inject_content"]["uri"]
        http_files = self.attachments_to_files(data)
        # Get
        if inject_contract == HTTP_GET_CONTRACT:
            response = session.get(url=url, headers=headers)
            return self._response_parsing(response)
        # Post
        if inject_contract == HTTP_RAW_POST_CONTRACT:
            body = data["injection"]["inject_content"]["body"]
            response = session.post(
                url=url, headers=headers, data=body, files=http_files
            )
            return self._response_parsing(response)
        # Put
        if inject_contract == HTTP_RAW_PUT_CONTRACT:
            body = data["injection"]["inject_content"]["body"]
            response = session.put(
                url=url, headers=headers, data=body, files=http_files
            )
            return self._response_parsing(response)
        # Form Post
        if inject_contract == HTTP_FORM_POST_CONTRACT:
            body = self._request_data_parts_body(data)
            response = session.post(
                url=url, headers=headers, data=body, files=http_files
            )
            return self._response_parsing(response)
        # Form Put
        if inject_contract == HTTP_FORM_PUT_CONTRACT:
            body = self._request_data_parts_body(data)
            response = session.put(
                url=url, headers=headers, data=body, files=http_files
            )
            return self._response_parsing(response)
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
            callback_data = {
                "execution_message": execution_result["message"],
                "execution_status": execution_result["status"],
                "execution_duration": int(time.time() - start),
                "execution_context_identifiers": None,
            }
            self.helper.api.inject.execution_callback(
                inject_id=inject_id, data=callback_data
            )
        except Exception as e:
            callback_data = {
                "execution_message": str(e),
                "execution_status": "ERROR",
                "execution_duration": int(time.time() - start),
                "execution_context_identifiers": None,
            }
            self.helper.api.inject.execution_callback(
                inject_id=inject_id, data=callback_data
            )

    # Start the main loop
    def start(self):
        self.helper.listen(message_callback=self.process_message)


if __name__ == "__main__":
    openBASHttp = OpenBASHttp()
    openBASHttp.start()
