import unittest
import uuid
from unittest import mock
from unittest.mock import MagicMock

from requests.exceptions import HTTPError

from nuclei.nuclei_contracts.external_contracts import ExternalContractsManager


class ExternalContractsTest(unittest.TestCase):
    INJECTOR_ID = uuid.uuid4()

    REPOSITORY_CVE_TEMPLATES = [
        '{"ID":"CVE-0001-0114","file_path":"filepath_1"}',
        '{"ID":"CVE-0002-0760","file_path":"filepath_2"}',
        '{"ID":"CVE-0003-0537","file_path":"filepath_3"}',
        '{"ID":"CVE-0004-1131","file_path":"filepath_4"}',
        '{"ID":"CVE-0005-0519","file_path":"filepath_5"}',
    ]

    def default_repository_templates_fetch(self, mock_session_get):
        mock_response = MagicMock()
        response_text = self.REPOSITORY_CVE_TEMPLATES
        mock_response.iter_lines.return_value = response_text
        mock_session_get.return_value = mock_response

    @mock.patch("requests.Session.get")
    def test_when_cant_fetch_from_github_raise_error(self, mock_requests_get):
        expected_exception_message = "got bad status {}".format(uuid.uuid4())
        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = HTTPError(
            expected_exception_message, response=self
        )
        mock_requests_get.return_value = mock_response

        tested = ExternalContractsManager(None, self.INJECTOR_ID)

        with self.assertRaises(HTTPError) as http_error:
            tested.manage_contracts()
        self.assertEqual(str(http_error.exception), expected_exception_message)

    @mock.patch("requests.Session.get")
    @mock.patch("pyobas.client.OpenBAS")
    def test_when_no_preexisting_contract_create_all_from_templates(
        self, mock_obas_client, mock_requests_get
    ):
        self.default_repository_templates_fetch(mock_requests_get)

        returned_contracts_page = {
            "content": [
                {
                    "injector_contract_external_id": "external-injector-contract_{}_{}".format(
                        self.INJECTOR_ID, uuid.uuid4()
                    )
                }
            ],
            "last": True,
        }

        mock_obas_client.injector_contract.search.return_value = returned_contracts_page

        tested = ExternalContractsManager(mock_obas_client, self.INJECTOR_ID)

        tested.manage_contracts()
