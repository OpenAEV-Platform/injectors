import unittest
import uuid
from unittest import mock
from unittest.mock import MagicMock, call

from pyoaev.contracts.contract_config import SupportedLanguage
from requests.exceptions import HTTPError

from nuclei.helpers.nuclei_process import NucleiProcess
from nuclei.nuclei_contracts.external_contracts import ExternalContractsManager


class ExternalContractsTest(unittest.TestCase):
    INJECTOR_ID = str(uuid.uuid4())
    LOGGER = MagicMock()

    REPOSITORY_CVE_TEMPLATES = [
        '{"ID":"CVE-0001-0114","file_path":"filepath_1"}',
        '{"ID":"CVE-0002-0760","file_path":"filepath_2"}',
        '{"ID":"CVE-0003-0537","file_path":"filepath_3"}',
        '{"ID":"CVE-0004-1131","file_path":"filepath_4"}',
        '{"ID":"CVE-0005-0519","file_path":"filepath_5"}',
    ]

    def setUp(self):
        self.LOGGER.log_level = "INFO"
        # permanently disable actual nuclei subprocess command
        NucleiProcess.nuclei_update_templates = lambda: None

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

        tested = ExternalContractsManager(None, self.INJECTOR_ID, self.LOGGER)

        with self.assertRaises(HTTPError) as http_error:
            tested.manage_contracts()
        self.assertEqual(str(http_error.exception), expected_exception_message)

    @mock.patch("requests.Session.get")
    @mock.patch("pyoaev.client.OpenAEV")
    @mock.patch("uuid.uuid4")
    def test_when_no_preexisting_contract_create_all_from_templates(
        self, mock_uuid4, mock_oaev_client, mock_requests_get
    ):
        generated_uuids = [
            "346605e6-0e00-4026-ad21-bad0ffc5f6a9",
            "c1a722b7-8c6f-4168-9b58-82370c40845e",
            "c4ce27f0-1211-428f-9afc-c710fb671abf",
            "027ef443-756e-4e6c-90c5-f1cedec62e51",
            "68c42050-fe01-4422-907a-0daad00dc246",
        ]
        # mock uuidv4 generation to get deterministic uuids for assertion
        mock_uuid4.side_effect = generated_uuids
        self.default_repository_templates_fetch(mock_requests_get)

        returned_contracts_page = {
            "content": [
                {
                    "injector_contract_external_id": "external-injector-contract_{}_0c3c6ede-3e5d-4d99-9cd9-d6ae6f3115d4".format(
                        self.INJECTOR_ID
                    )
                }
            ],
            "last": True,
        }

        mock_oaev_client.injector_contract.search.return_value = returned_contracts_page

        tested = ExternalContractsManager(
            mock_oaev_client, self.INJECTOR_ID, self.LOGGER
        )

        tested.manage_contracts()

        mock_oaev_client.injector_contract.update.assert_not_called()

        mock_oaev_client.injector_contract.delete.assert_has_calls(
            calls=[
                call(
                    "external-injector-contract_{}_0c3c6ede-3e5d-4d99-9cd9-d6ae6f3115d4".format(
                        self.INJECTOR_ID
                    )
                ),
            ]
        )

        mock_oaev_client.injector_contract.create.assert_has_calls(
            calls=[
                call(
                    {
                        "contract_id": generated_uuids[0],
                        "external_contract_id": "external-injector-contract_{}_CVE-0001-0114".format(
                            self.INJECTOR_ID
                        ),
                        "injector_id": self.INJECTOR_ID,
                        "contract_manual": False,
                        "contract_labels": {
                            SupportedLanguage.en: "CVE-0001-0114",
                            SupportedLanguage.fr: "CVE-0001-0114",
                        },
                        "contract_attack_patterns_external_ids": [],
                        "contract_vulnerability_external_ids": ["CVE-0001-0114"],
                        "contract_content": '{"contract_id": "'
                        + generated_uuids[0]
                        + '", "label": {"en": "CVE-0001-0114", "fr": "CVE-0001-0114"}, "fields": ['
                        '{"key": "target_selector", "label": "Type of targets", "type": "select", "mandatoryGroups": [], "mandatoryConditionFields": [], "mandatoryConditionValues": [], "visibleConditionFields": [], "visibleConditionValues": [], "linkedFields": [], "mandatory": true, "readOnly": false, "cardinality": "1", "defaultValue": ["asset-groups"], "choices": {"assets": "Assets", "manual": "Manual", "asset-groups": "Asset groups"}}, '
                        '{"key": "assets", "label": "Targeted assets", "type": "asset", "mandatoryGroups": [], "mandatoryConditionFields": ["target_selector"], '
                        '"mandatoryConditionValues": {"target_selector": "assets"}, "visibleConditionFields": ["target_selector"], '
                        '"visibleConditionValues": {"target_selector": "assets"}, "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "n", "defaultValue": []}, '
                        '{"key": "asset_groups", "label": "Targeted asset groups", "type": "asset-group", "mandatoryGroups": [], "mandatoryConditionFields": ["target_selector"], "mandatoryConditionValues": {"target_selector": "asset-groups"}, "visibleConditionFields": ["target_selector"], "visibleConditionValues": {"target_selector": "asset-groups"}, "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "n", "defaultValue": []}, '
                        '{"key": "target_property_selector", "label": "Targeted assets property", "type": "select", "mandatoryGroups": [], "mandatoryConditionFields": ["target_selector"], "mandatoryConditionValues": {"target_selector": ["assets", "asset-groups"]}, "visibleConditionFields": ["target_selector"], "visibleConditionValues": {"target_selector": ["assets", "asset-groups"]}, "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "1", "defaultValue": ["automatic"], "choices": {"automatic": "Automatic", "hostname": "Hostname", "seen_ip": "Seen IP", "local_ip": "Local IP (first)"}}, '
                        '{"key": "targets", "label": "Manual targets (comma-separated)", "type": "text", "mandatoryGroups": [], "mandatoryConditionFields": ["target_selector"], "mandatoryConditionValues": {"target_selector": "manual"}, "visibleConditionFields": ["target_selector"], "visibleConditionValues": {"target_selector": "manual"}, "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "1", "defaultValue": ""}, '
                        '{"key": "expectations", "label": "Expectations", "type": "expectation", "mandatoryGroups": [], "mandatoryConditionFields": [], "mandatoryConditionValues": [], "visibleConditionFields": [], "visibleConditionValues": [], "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "n", "defaultValue": [], "predefinedExpectations": [{"expectation_type": "VULNERABILITY", "expectation_name": "Not vulnerable", "expectation_description": "", "expectation_score": 100, "expectation_expectation_group": false}]}, '
                        '{"key": "template", "label": "Manual template path (-t)", "type": "text", "mandatoryGroups": [], "mandatoryConditionFields": [], "mandatoryConditionValues": [], "visibleConditionFields": [], "visibleConditionValues": [], "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "1", "defaultValue": ["filepath_1"]}, '
                        '{"key": "options", "label": "Options", "type": "text", "mandatoryGroups": [], "mandatoryConditionFields": [], "mandatoryConditionValues": [], "visibleConditionFields": [], "visibleConditionValues": [], "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "1", "defaultValue": ""}], '
                        '"outputs": [{"type": "cve", "field": "cve", "labels": ["nuclei"], "isFindingCompatible": true, "isMultiple": true}, {"type": "text", "field": "others", "labels": ["nuclei"], "isFindingCompatible": true, "isMultiple": true}], '
                        '"config": {"type": "openaev_nuclei", "expose": true, "label": {"en": "Nuclei Scan", "fr": "Nuclei Scan"}, "color_dark": "#ff5722", "color_light": "#ff5722"}, "manual": false, '
                        '"variables": [{"key": "user", "label": "User that will receive the injection", "type": "String", "cardinality": "1", "children": [{"key": "user.id", "label": "Id of the user in the platform", "type": "String", "cardinality": "1", "children": []}, {"key": "user.email", "label": "Email of the user", "type": "String", "cardinality": "1", "children": []}, {"key": "user.firstname", "label": "Firstname of the user", "type": "String", "cardinality": "1", "children": []}, {"key": "user.lastname", "label": "Lastname of the user", "type": "String", "cardinality": "1", "children": []}, {"key": "user.lang", "label": "Lang of the user", "type": "String", "cardinality": "1", "children": []}]}, {"key": "exercise", "label": "Exercise of the current injection", "type": "Object", "cardinality": "1", "children": [{"key": "exercise.id", "label": "Id of the exercise in the platform", "type": "String", "cardinality": "1", "children": []}, {"key": "exercise.name", "label": "Name of the exercise", "type": "String", "cardinality": "1", "children": []}, {"key": "exercise.description", "label": "Description of the exercise", "type": "String", "cardinality": "1", "children": []}]}, {"key": "teams", "label": "List of team name for the injection", "type": "String", "cardinality": "n", "children": []}, {"key": "player_uri", "label": "Player interface platform link", "type": "String", "cardinality": "1", "children": []}, {"key": "challenges_uri", "label": "Challenges interface platform link", "type": "String", "cardinality": "1", "children": []}, {"key": "scoreboard_uri", "label": "Scoreboard interface platform link", "type": "String", "cardinality": "1", "children": []}, {"key": "lessons_uri", "label": "Lessons learned interface platform link", "type": "String", "cardinality": "1", "children": []}], '
                        '"contract_attack_patterns_external_ids": [], "contract_vulnerability_external_ids": ["CVE-0001-0114"], "is_atomic_testing": true, "platforms": [], "external_id": "external-injector-contract_'
                        + self.INJECTOR_ID
                        + '_CVE-0001-0114", "domains": [{"domain_name": "Network", "domain_color": "#009933"}]}',
                        "is_atomic_testing": True,
                        "contract_platforms": [],
                        "contract_domains": [
                            {"domain_name": "Network", "domain_color": "#009933"}
                        ],
                    }
                ),
                call(
                    {
                        "contract_id": generated_uuids[1],
                        "external_contract_id": "external-injector-contract_{}_CVE-0002-0760".format(
                            self.INJECTOR_ID
                        ),
                        "injector_id": self.INJECTOR_ID,
                        "contract_manual": False,
                        "contract_labels": {
                            SupportedLanguage.en: "CVE-0002-0760",
                            SupportedLanguage.fr: "CVE-0002-0760",
                        },
                        "contract_attack_patterns_external_ids": [],
                        "contract_vulnerability_external_ids": ["CVE-0002-0760"],
                        "contract_content": '{"contract_id": "'
                        + generated_uuids[1]
                        + '", "label": {"en": "CVE-0002-0760", "fr": "CVE-0002-0760"}, "fields": ['
                        '{"key": "target_selector", "label": "Type of targets", "type": "select", "mandatoryGroups": [], "mandatoryConditionFields": [], "mandatoryConditionValues": [], "visibleConditionFields": [], "visibleConditionValues": [], "linkedFields": [], "mandatory": true, "readOnly": false, "cardinality": "1", "defaultValue": ["asset-groups"], "choices": {"assets": "Assets", "manual": "Manual", "asset-groups": "Asset groups"}}, '
                        '{"key": "assets", "label": "Targeted assets", "type": "asset", "mandatoryGroups": [], "mandatoryConditionFields": ["target_selector"], '
                        '"mandatoryConditionValues": {"target_selector": "assets"}, "visibleConditionFields": ["target_selector"], '
                        '"visibleConditionValues": {"target_selector": "assets"}, "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "n", "defaultValue": []}, '
                        '{"key": "asset_groups", "label": "Targeted asset groups", "type": "asset-group", "mandatoryGroups": [], "mandatoryConditionFields": ["target_selector"], "mandatoryConditionValues": {"target_selector": "asset-groups"}, "visibleConditionFields": ["target_selector"], "visibleConditionValues": {"target_selector": "asset-groups"}, "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "n", "defaultValue": []}, '
                        '{"key": "target_property_selector", "label": "Targeted assets property", "type": "select", "mandatoryGroups": [], "mandatoryConditionFields": ["target_selector"], "mandatoryConditionValues": {"target_selector": ["assets", "asset-groups"]}, "visibleConditionFields": ["target_selector"], "visibleConditionValues": {"target_selector": ["assets", "asset-groups"]}, "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "1", "defaultValue": ["automatic"], "choices": {"automatic": "Automatic", "hostname": "Hostname", "seen_ip": "Seen IP", "local_ip": "Local IP (first)"}}, '
                        '{"key": "targets", "label": "Manual targets (comma-separated)", "type": "text", "mandatoryGroups": [], "mandatoryConditionFields": ["target_selector"], "mandatoryConditionValues": {"target_selector": "manual"}, "visibleConditionFields": ["target_selector"], "visibleConditionValues": {"target_selector": "manual"}, "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "1", "defaultValue": ""}, '
                        '{"key": "expectations", "label": "Expectations", "type": "expectation", "mandatoryGroups": [], "mandatoryConditionFields": [], "mandatoryConditionValues": [], "visibleConditionFields": [], "visibleConditionValues": [], "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "n", "defaultValue": [], "predefinedExpectations": [{"expectation_type": "VULNERABILITY", "expectation_name": "Not vulnerable", "expectation_description": "", "expectation_score": 100, "expectation_expectation_group": false}]}, '
                        '{"key": "template", "label": "Manual template path (-t)", "type": "text", "mandatoryGroups": [], "mandatoryConditionFields": [], "mandatoryConditionValues": [], "visibleConditionFields": [], "visibleConditionValues": [], "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "1", "defaultValue": ["filepath_2"]}, '
                        '{"key": "options", "label": "Options", "type": "text", "mandatoryGroups": [], "mandatoryConditionFields": [], "mandatoryConditionValues": [], "visibleConditionFields": [], "visibleConditionValues": [], "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "1", "defaultValue": ""}], '
                        '"outputs": [{"type": "cve", "field": "cve", "labels": ["nuclei"], "isFindingCompatible": true, "isMultiple": true}, {"type": "text", "field": "others", "labels": ["nuclei"], "isFindingCompatible": true, "isMultiple": true}], '
                        '"config": {"type": "openaev_nuclei", "expose": true, "label": {"en": "Nuclei Scan", "fr": "Nuclei Scan"}, "color_dark": "#ff5722", "color_light": "#ff5722"}, "manual": false, '
                        '"variables": [{"key": "user", "label": "User that will receive the injection", "type": "String", "cardinality": "1", "children": [{"key": "user.id", "label": "Id of the user in the platform", "type": "String", "cardinality": "1", "children": []}, {"key": "user.email", "label": "Email of the user", "type": "String", "cardinality": "1", "children": []}, {"key": "user.firstname", "label": "Firstname of the user", "type": "String", "cardinality": "1", "children": []}, {"key": "user.lastname", "label": "Lastname of the user", "type": "String", "cardinality": "1", "children": []}, {"key": "user.lang", "label": "Lang of the user", "type": "String", "cardinality": "1", "children": []}]}, {"key": "exercise", "label": "Exercise of the current injection", "type": "Object", "cardinality": "1", "children": [{"key": "exercise.id", "label": "Id of the exercise in the platform", "type": "String", "cardinality": "1", "children": []}, {"key": "exercise.name", "label": "Name of the exercise", "type": "String", "cardinality": "1", "children": []}, {"key": "exercise.description", "label": "Description of the exercise", "type": "String", "cardinality": "1", "children": []}]}, {"key": "teams", "label": "List of team name for the injection", "type": "String", "cardinality": "n", "children": []}, {"key": "player_uri", "label": "Player interface platform link", "type": "String", "cardinality": "1", "children": []}, {"key": "challenges_uri", "label": "Challenges interface platform link", "type": "String", "cardinality": "1", "children": []}, {"key": "scoreboard_uri", "label": "Scoreboard interface platform link", "type": "String", "cardinality": "1", "children": []}, {"key": "lessons_uri", "label": "Lessons learned interface platform link", "type": "String", "cardinality": "1", "children": []}], '
                        '"contract_attack_patterns_external_ids": [], "contract_vulnerability_external_ids": ["CVE-0002-0760"], "is_atomic_testing": true, "platforms": [], "external_id": "external-injector-contract_'
                        + self.INJECTOR_ID
                        + '_CVE-0002-0760", "domains": [{"domain_name": "Network", "domain_color": "#009933"}]}',
                        "is_atomic_testing": True,
                        "contract_platforms": [],
                        "contract_domains": [
                            {"domain_name": "Network", "domain_color": "#009933"}
                        ],
                    }
                ),
                call(
                    {
                        "contract_id": generated_uuids[2],
                        "external_contract_id": "external-injector-contract_{}_CVE-0003-0537".format(
                            self.INJECTOR_ID
                        ),
                        "injector_id": self.INJECTOR_ID,
                        "contract_manual": False,
                        "contract_labels": {
                            SupportedLanguage.en: "CVE-0003-0537",
                            SupportedLanguage.fr: "CVE-0003-0537",
                        },
                        "contract_attack_patterns_external_ids": [],
                        "contract_vulnerability_external_ids": ["CVE-0003-0537"],
                        "contract_content": '{"contract_id": "'
                        + generated_uuids[2]
                        + '", "label": {"en": "CVE-0003-0537", "fr": "CVE-0003-0537"}, "fields": ['
                        '{"key": "target_selector", "label": "Type of targets", "type": "select", "mandatoryGroups": [], "mandatoryConditionFields": [], "mandatoryConditionValues": [], "visibleConditionFields": [], "visibleConditionValues": [], "linkedFields": [], "mandatory": true, "readOnly": false, "cardinality": "1", "defaultValue": ["asset-groups"], "choices": {"assets": "Assets", "manual": "Manual", "asset-groups": "Asset groups"}}, '
                        '{"key": "assets", "label": "Targeted assets", "type": "asset", "mandatoryGroups": [], "mandatoryConditionFields": ["target_selector"], '
                        '"mandatoryConditionValues": {"target_selector": "assets"}, "visibleConditionFields": ["target_selector"], '
                        '"visibleConditionValues": {"target_selector": "assets"}, "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "n", "defaultValue": []}, '
                        '{"key": "asset_groups", "label": "Targeted asset groups", "type": "asset-group", "mandatoryGroups": [], "mandatoryConditionFields": ["target_selector"], "mandatoryConditionValues": {"target_selector": "asset-groups"}, "visibleConditionFields": ["target_selector"], "visibleConditionValues": {"target_selector": "asset-groups"}, "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "n", "defaultValue": []}, '
                        '{"key": "target_property_selector", "label": "Targeted assets property", "type": "select", "mandatoryGroups": [], "mandatoryConditionFields": ["target_selector"], "mandatoryConditionValues": {"target_selector": ["assets", "asset-groups"]}, "visibleConditionFields": ["target_selector"], "visibleConditionValues": {"target_selector": ["assets", "asset-groups"]}, "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "1", "defaultValue": ["automatic"], "choices": {"automatic": "Automatic", "hostname": "Hostname", "seen_ip": "Seen IP", "local_ip": "Local IP (first)"}}, '
                        '{"key": "targets", "label": "Manual targets (comma-separated)", "type": "text", "mandatoryGroups": [], "mandatoryConditionFields": ["target_selector"], "mandatoryConditionValues": {"target_selector": "manual"}, "visibleConditionFields": ["target_selector"], "visibleConditionValues": {"target_selector": "manual"}, "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "1", "defaultValue": ""}, '
                        '{"key": "expectations", "label": "Expectations", "type": "expectation", "mandatoryGroups": [], "mandatoryConditionFields": [], "mandatoryConditionValues": [], "visibleConditionFields": [], "visibleConditionValues": [], "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "n", "defaultValue": [], "predefinedExpectations": [{"expectation_type": "VULNERABILITY", "expectation_name": "Not vulnerable", "expectation_description": "", "expectation_score": 100, "expectation_expectation_group": false}]}, '
                        '{"key": "template", "label": "Manual template path (-t)", "type": "text", "mandatoryGroups": [], "mandatoryConditionFields": [], "mandatoryConditionValues": [], "visibleConditionFields": [], "visibleConditionValues": [], "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "1", "defaultValue": ["filepath_3"]}, '
                        '{"key": "options", "label": "Options", "type": "text", "mandatoryGroups": [], "mandatoryConditionFields": [], "mandatoryConditionValues": [], "visibleConditionFields": [], "visibleConditionValues": [], "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "1", "defaultValue": ""}], '
                        '"outputs": [{"type": "cve", "field": "cve", "labels": ["nuclei"], "isFindingCompatible": true, "isMultiple": true}, {"type": "text", "field": "others", "labels": ["nuclei"], "isFindingCompatible": true, "isMultiple": true}], '
                        '"config": {"type": "openaev_nuclei", "expose": true, "label": {"en": "Nuclei Scan", "fr": "Nuclei Scan"}, "color_dark": "#ff5722", "color_light": "#ff5722"}, "manual": false, '
                        '"variables": [{"key": "user", "label": "User that will receive the injection", "type": "String", "cardinality": "1", "children": [{"key": "user.id", "label": "Id of the user in the platform", "type": "String", "cardinality": "1", "children": []}, {"key": "user.email", "label": "Email of the user", "type": "String", "cardinality": "1", "children": []}, {"key": "user.firstname", "label": "Firstname of the user", "type": "String", "cardinality": "1", "children": []}, {"key": "user.lastname", "label": "Lastname of the user", "type": "String", "cardinality": "1", "children": []}, {"key": "user.lang", "label": "Lang of the user", "type": "String", "cardinality": "1", "children": []}]}, {"key": "exercise", "label": "Exercise of the current injection", "type": "Object", "cardinality": "1", "children": [{"key": "exercise.id", "label": "Id of the exercise in the platform", "type": "String", "cardinality": "1", "children": []}, {"key": "exercise.name", "label": "Name of the exercise", "type": "String", "cardinality": "1", "children": []}, {"key": "exercise.description", "label": "Description of the exercise", "type": "String", "cardinality": "1", "children": []}]}, {"key": "teams", "label": "List of team name for the injection", "type": "String", "cardinality": "n", "children": []}, {"key": "player_uri", "label": "Player interface platform link", "type": "String", "cardinality": "1", "children": []}, {"key": "challenges_uri", "label": "Challenges interface platform link", "type": "String", "cardinality": "1", "children": []}, {"key": "scoreboard_uri", "label": "Scoreboard interface platform link", "type": "String", "cardinality": "1", "children": []}, {"key": "lessons_uri", "label": "Lessons learned interface platform link", "type": "String", "cardinality": "1", "children": []}], '
                        '"contract_attack_patterns_external_ids": [], "contract_vulnerability_external_ids": ["CVE-0003-0537"], "is_atomic_testing": true, "platforms": [], "external_id": "external-injector-contract_'
                        + self.INJECTOR_ID
                        + '_CVE-0003-0537", "domains": [{"domain_name": "Network", "domain_color": "#009933"}]}',
                        "is_atomic_testing": True,
                        "contract_platforms": [],
                        "contract_domains": [
                            {"domain_name": "Network", "domain_color": "#009933"}
                        ],
                    }
                ),
                call(
                    {
                        "contract_id": generated_uuids[3],
                        "external_contract_id": "external-injector-contract_{}_CVE-0004-1131".format(
                            self.INJECTOR_ID
                        ),
                        "injector_id": self.INJECTOR_ID,
                        "contract_manual": False,
                        "contract_labels": {
                            SupportedLanguage.en: "CVE-0004-1131",
                            SupportedLanguage.fr: "CVE-0004-1131",
                        },
                        "contract_attack_patterns_external_ids": [],
                        "contract_vulnerability_external_ids": ["CVE-0004-1131"],
                        "contract_content": '{"contract_id": "'
                        + generated_uuids[3]
                        + '", "label": {"en": "CVE-0004-1131", "fr": "CVE-0004-1131"}, "fields": ['
                        '{"key": "target_selector", "label": "Type of targets", "type": "select", "mandatoryGroups": [], "mandatoryConditionFields": [], "mandatoryConditionValues": [], "visibleConditionFields": [], "visibleConditionValues": [], "linkedFields": [], "mandatory": true, "readOnly": false, "cardinality": "1", "defaultValue": ["asset-groups"], "choices": {"assets": "Assets", "manual": "Manual", "asset-groups": "Asset groups"}}, '
                        '{"key": "assets", "label": "Targeted assets", "type": "asset", "mandatoryGroups": [], "mandatoryConditionFields": ["target_selector"], '
                        '"mandatoryConditionValues": {"target_selector": "assets"}, "visibleConditionFields": ["target_selector"], '
                        '"visibleConditionValues": {"target_selector": "assets"}, "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "n", "defaultValue": []}, '
                        '{"key": "asset_groups", "label": "Targeted asset groups", "type": "asset-group", "mandatoryGroups": [], "mandatoryConditionFields": ["target_selector"], "mandatoryConditionValues": {"target_selector": "asset-groups"}, "visibleConditionFields": ["target_selector"], "visibleConditionValues": {"target_selector": "asset-groups"}, "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "n", "defaultValue": []}, '
                        '{"key": "target_property_selector", "label": "Targeted assets property", "type": "select", "mandatoryGroups": [], "mandatoryConditionFields": ["target_selector"], "mandatoryConditionValues": {"target_selector": ["assets", "asset-groups"]}, "visibleConditionFields": ["target_selector"], "visibleConditionValues": {"target_selector": ["assets", "asset-groups"]}, "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "1", "defaultValue": ["automatic"], "choices": {"automatic": "Automatic", "hostname": "Hostname", "seen_ip": "Seen IP", "local_ip": "Local IP (first)"}}, '
                        '{"key": "targets", "label": "Manual targets (comma-separated)", "type": "text", "mandatoryGroups": [], "mandatoryConditionFields": ["target_selector"], "mandatoryConditionValues": {"target_selector": "manual"}, "visibleConditionFields": ["target_selector"], "visibleConditionValues": {"target_selector": "manual"}, "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "1", "defaultValue": ""}, '
                        '{"key": "expectations", "label": "Expectations", "type": "expectation", "mandatoryGroups": [], "mandatoryConditionFields": [], "mandatoryConditionValues": [], "visibleConditionFields": [], "visibleConditionValues": [], "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "n", "defaultValue": [], "predefinedExpectations": [{"expectation_type": "VULNERABILITY", "expectation_name": "Not vulnerable", "expectation_description": "", "expectation_score": 100, "expectation_expectation_group": false}]}, '
                        '{"key": "template", "label": "Manual template path (-t)", "type": "text", "mandatoryGroups": [], "mandatoryConditionFields": [], "mandatoryConditionValues": [], "visibleConditionFields": [], "visibleConditionValues": [], "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "1", "defaultValue": ["filepath_4"]}, '
                        '{"key": "options", "label": "Options", "type": "text", "mandatoryGroups": [], "mandatoryConditionFields": [], "mandatoryConditionValues": [], "visibleConditionFields": [], "visibleConditionValues": [], "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "1", "defaultValue": ""}], '
                        '"outputs": [{"type": "cve", "field": "cve", "labels": ["nuclei"], "isFindingCompatible": true, "isMultiple": true}, {"type": "text", "field": "others", "labels": ["nuclei"], "isFindingCompatible": true, "isMultiple": true}], '
                        '"config": {"type": "openaev_nuclei", "expose": true, "label": {"en": "Nuclei Scan", "fr": "Nuclei Scan"}, "color_dark": "#ff5722", "color_light": "#ff5722"}, "manual": false, '
                        '"variables": [{"key": "user", "label": "User that will receive the injection", "type": "String", "cardinality": "1", "children": [{"key": "user.id", "label": "Id of the user in the platform", "type": "String", "cardinality": "1", "children": []}, {"key": "user.email", "label": "Email of the user", "type": "String", "cardinality": "1", "children": []}, {"key": "user.firstname", "label": "Firstname of the user", "type": "String", "cardinality": "1", "children": []}, {"key": "user.lastname", "label": "Lastname of the user", "type": "String", "cardinality": "1", "children": []}, {"key": "user.lang", "label": "Lang of the user", "type": "String", "cardinality": "1", "children": []}]}, {"key": "exercise", "label": "Exercise of the current injection", "type": "Object", "cardinality": "1", "children": [{"key": "exercise.id", "label": "Id of the exercise in the platform", "type": "String", "cardinality": "1", "children": []}, {"key": "exercise.name", "label": "Name of the exercise", "type": "String", "cardinality": "1", "children": []}, {"key": "exercise.description", "label": "Description of the exercise", "type": "String", "cardinality": "1", "children": []}]}, {"key": "teams", "label": "List of team name for the injection", "type": "String", "cardinality": "n", "children": []}, {"key": "player_uri", "label": "Player interface platform link", "type": "String", "cardinality": "1", "children": []}, {"key": "challenges_uri", "label": "Challenges interface platform link", "type": "String", "cardinality": "1", "children": []}, {"key": "scoreboard_uri", "label": "Scoreboard interface platform link", "type": "String", "cardinality": "1", "children": []}, {"key": "lessons_uri", "label": "Lessons learned interface platform link", "type": "String", "cardinality": "1", "children": []}], '
                        '"contract_attack_patterns_external_ids": [], "contract_vulnerability_external_ids": ["CVE-0004-1131"], "is_atomic_testing": true, "platforms": [], "external_id": "external-injector-contract_'
                        + self.INJECTOR_ID
                        + '_CVE-0004-1131", "domains": [{"domain_name": "Network", "domain_color": "#009933"}]}',
                        "is_atomic_testing": True,
                        "contract_platforms": [],
                        "contract_domains": [
                            {"domain_name": "Network", "domain_color": "#009933"}
                        ],
                    }
                ),
                call(
                    {
                        "contract_id": generated_uuids[4],
                        "external_contract_id": "external-injector-contract_{}_CVE-0005-0519".format(
                            self.INJECTOR_ID
                        ),
                        "injector_id": self.INJECTOR_ID,
                        "contract_manual": False,
                        "contract_labels": {
                            SupportedLanguage.en: "CVE-0005-0519",
                            SupportedLanguage.fr: "CVE-0005-0519",
                        },
                        "contract_attack_patterns_external_ids": [],
                        "contract_vulnerability_external_ids": ["CVE-0005-0519"],
                        "contract_content": '{"contract_id": "'
                        + generated_uuids[4]
                        + '", "label": {"en": "CVE-0005-0519", "fr": "CVE-0005-0519"}, "fields": [{"key": "target_selector", "label": "Type of targets", "type": "select", "mandatoryGroups": [], "mandatoryConditionFields": [], "mandatoryConditionValues": [], "visibleConditionFields": [], "visibleConditionValues": [], "linkedFields": [], "mandatory": true, "readOnly": false, "cardinality": "1", "defaultValue": ["asset-groups"], "choices": {"assets": "Assets", "manual": "Manual", "asset-groups": "Asset groups"}}, {"key": "assets", "label": "Targeted assets", "type": "asset", "mandatoryGroups": [], "mandatoryConditionFields": ["target_selector"], "mandatoryConditionValues": {"target_selector": "assets"}, "visibleConditionFields": ["target_selector"], "visibleConditionValues": {"target_selector": "assets"}, "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "n", "defaultValue": []}, {"key": "asset_groups", "label": "Targeted asset groups", "type": "asset-group", "mandatoryGroups": [], "mandatoryConditionFields": ["target_selector"], "mandatoryConditionValues": {"target_selector": "asset-groups"}, "visibleConditionFields": ["target_selector"], "visibleConditionValues": {"target_selector": "asset-groups"}, "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "n", "defaultValue": []}, {"key": "target_property_selector", "label": "Targeted assets property", "type": "select", "mandatoryGroups": [], "mandatoryConditionFields": ["target_selector"], "mandatoryConditionValues": {"target_selector": ["assets", "asset-groups"]}, "visibleConditionFields": ["target_selector"], "visibleConditionValues": {"target_selector": ["assets", "asset-groups"]}, "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "1", "defaultValue": ["automatic"], "choices": {"automatic": "Automatic", "hostname": "Hostname", "seen_ip": "Seen IP", "local_ip": "Local IP (first)"}}, {"key": "targets", "label": "Manual targets (comma-separated)", "type": "text", "mandatoryGroups": [], "mandatoryConditionFields": ["target_selector"], "mandatoryConditionValues": {"target_selector": "manual"}, "visibleConditionFields": ["target_selector"], "visibleConditionValues": {"target_selector": "manual"}, "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "1", "defaultValue": ""}, {"key": "expectations", "label": "Expectations", "type": "expectation", "mandatoryGroups": [], "mandatoryConditionFields": [], "mandatoryConditionValues": [], "visibleConditionFields": [], "visibleConditionValues": [], "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "n", "defaultValue": [], "predefinedExpectations": [{"expectation_type": "VULNERABILITY", "expectation_name": "Not vulnerable", "expectation_description": "", "expectation_score": 100, "expectation_expectation_group": false}]}, '
                        '{"key": "template", "label": "Manual template path (-t)", "type": "text", "mandatoryGroups": [], "mandatoryConditionFields": [], "mandatoryConditionValues": [], "visibleConditionFields": [], "visibleConditionValues": [], "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "1", "defaultValue": ["filepath_5"]}, '
                        '{"key": "options", "label": "Options", "type": "text", "mandatoryGroups": [], "mandatoryConditionFields": [], "mandatoryConditionValues": [], "visibleConditionFields": [], "visibleConditionValues": [], "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "1", "defaultValue": ""}], "outputs": [{"type": "cve", "field": "cve", "labels": ["nuclei"], "isFindingCompatible": true, "isMultiple": true}, {"type": "text", "field": "others", "labels": ["nuclei"], "isFindingCompatible": true, "isMultiple": true}], "config": {"type": "openaev_nuclei", "expose": true, "label": {"en": "Nuclei Scan", "fr": "Nuclei Scan"}, "color_dark": "#ff5722", "color_light": "#ff5722"}, "manual": false, "variables": [{"key": "user", "label": "User that will receive the injection", "type": "String", "cardinality": "1", "children": [{"key": "user.id", "label": "Id of the user in the platform", "type": "String", "cardinality": "1", "children": []}, {"key": "user.email", "label": "Email of the user", "type": "String", "cardinality": "1", "children": []}, {"key": "user.firstname", "label": "Firstname of the user", "type": "String", "cardinality": "1", "children": []}, {"key": "user.lastname", "label": "Lastname of the user", "type": "String", "cardinality": "1", "children": []}, {"key": "user.lang", "label": "Lang of the user", "type": "String", "cardinality": "1", "children": []}]}, {"key": "exercise", "label": "Exercise of the current injection", "type": "Object", "cardinality": "1", "children": [{"key": "exercise.id", "label": "Id of the exercise in the platform", "type": "String", "cardinality": "1", "children": []}, {"key": "exercise.name", "label": "Name of the exercise", "type": "String", "cardinality": "1", "children": []}, {"key": "exercise.description", "label": "Description of the exercise", "type": "String", "cardinality": "1", "children": []}]}, {"key": "teams", "label": "List of team name for the injection", "type": "String", "cardinality": "n", "children": []}, {"key": "player_uri", "label": "Player interface platform link", "type": "String", "cardinality": "1", "children": []}, {"key": "challenges_uri", "label": "Challenges interface platform link", "type": "String", "cardinality": "1", "children": []}, {"key": "scoreboard_uri", "label": "Scoreboard interface platform link", "type": "String", "cardinality": "1", "children": []}, {"key": "lessons_uri", "label": "Lessons learned interface platform link", "type": "String", "cardinality": "1", "children": []}], "contract_attack_patterns_external_ids": [], "contract_vulnerability_external_ids": ["CVE-0005-0519"], "is_atomic_testing": true, "platforms": [], "external_id": "external-injector-contract_'
                        + self.INJECTOR_ID
                        + '_CVE-0005-0519", "domains": [{"domain_name": "Network", "domain_color": "#009933"}]}',
                        "is_atomic_testing": True,
                        "contract_platforms": [],
                        "contract_domains": [
                            {"domain_name": "Network", "domain_color": "#009933"}
                        ],
                    }
                ),
            ]
        )

    @mock.patch("requests.Session.get")
    @mock.patch("pyoaev.client.OpenAEV")
    @mock.patch("uuid.uuid4")
    def test_when_some_preexisting_contract_create_rest_from_templates(
        self, mock_uuid4, mock_oaev_client, mock_requests_get
    ):
        generated_uuids = [
            "346605e6-0e00-4026-ad21-bad0ffc5f6a9",
            "c1a722b7-8c6f-4168-9b58-82370c40845e",
            "c4ce27f0-1211-428f-9afc-c710fb671abf",
        ]
        # mock uuidv4 generation to get deterministic uuids for assertion
        mock_uuid4.side_effect = generated_uuids
        self.default_repository_templates_fetch(mock_requests_get)

        returned_contracts_page = {
            "content": [
                {
                    "injector_contract_id": "contract_to_delete_1",
                    "injector_contract_external_id": "external-injector-contract_{}_0c3c6ede-3e5d-4d99-9cd9-d6ae6f3115d4".format(
                        self.INJECTOR_ID
                    ),
                },
                {
                    "injector_contract_id": "contract_to_keep_2",
                    "injector_contract_external_id": "external-injector-contract_{}_CVE-0004-1131".format(
                        self.INJECTOR_ID
                    ),
                },
                {
                    "injector_contract_id": "contract_to_keep_3",
                    "injector_contract_external_id": "external-injector-contract_{}_CVE-0005-0519".format(
                        self.INJECTOR_ID
                    ),
                },
            ],
            "last": True,
        }

        mock_oaev_client.injector_contract.search.return_value = returned_contracts_page

        tested = ExternalContractsManager(
            mock_oaev_client, self.INJECTOR_ID, self.LOGGER
        )

        tested.manage_contracts()

        self.assertEqual(len(mock_oaev_client.injector_contract.delete.mock_calls), 1)
        mock_oaev_client.injector_contract.delete.assert_has_calls(
            calls=[
                call(
                    "external-injector-contract_{}_0c3c6ede-3e5d-4d99-9cd9-d6ae6f3115d4".format(
                        self.INJECTOR_ID
                    )
                ),
            ]
        )

        self.assertEqual(len(mock_oaev_client.injector_contract.update.mock_calls), 2)
        mock_oaev_client.injector_contract.update.assert_has_calls(
            calls=[
                call(
                    "external-injector-contract_{}_CVE-0004-1131".format(
                        self.INJECTOR_ID
                    ),
                    {
                        "contract_manual": False,
                        "contract_labels": {
                            SupportedLanguage.en: "CVE-0004-1131",
                            SupportedLanguage.fr: "CVE-0004-1131",
                        },
                        "contract_attack_patterns_external_ids": [],
                        "contract_vulnerability_external_ids": ["CVE-0004-1131"],
                        "contract_content": '{"contract_id": "contract_to_keep_2", "label": {"en": "CVE-0004-1131", "fr": "CVE-0004-1131"}, "fields": [{"key": "target_selector", "label": "Type of targets", "type": "select", "mandatoryGroups": [], "mandatoryConditionFields": [], "mandatoryConditionValues": [], "visibleConditionFields": [], "visibleConditionValues": [], "linkedFields": [], "mandatory": true, "readOnly": false, "cardinality": "1", "defaultValue": ["asset-groups"], "choices": {"assets": "Assets", "manual": "Manual", "asset-groups": "Asset groups"}}, {"key": "assets", "label": "Targeted assets", "type": "asset", "mandatoryGroups": [], "mandatoryConditionFields": ["target_selector"], "mandatoryConditionValues": {"target_selector": "assets"}, "visibleConditionFields": ["target_selector"], "visibleConditionValues": {"target_selector": "assets"}, "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "n", "defaultValue": []}, {"key": "asset_groups", "label": "Targeted asset groups", "type": "asset-group", "mandatoryGroups": [], "mandatoryConditionFields": ["target_selector"], "mandatoryConditionValues": {"target_selector": "asset-groups"}, "visibleConditionFields": ["target_selector"], "visibleConditionValues": {"target_selector": "asset-groups"}, "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "n", "defaultValue": []}, {"key": "target_property_selector", "label": "Targeted assets property", "type": "select", "mandatoryGroups": [], "mandatoryConditionFields": ["target_selector"], "mandatoryConditionValues": {"target_selector": ["assets", "asset-groups"]}, "visibleConditionFields": ["target_selector"], "visibleConditionValues": {"target_selector": ["assets", "asset-groups"]}, "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "1", "defaultValue": ["automatic"], "choices": {"automatic": "Automatic", "hostname": "Hostname", "seen_ip": "Seen IP", "local_ip": "Local IP (first)"}}, {"key": "targets", "label": "Manual targets (comma-separated)", "type": "text", "mandatoryGroups": [], "mandatoryConditionFields": ["target_selector"], "mandatoryConditionValues": {"target_selector": "manual"}, "visibleConditionFields": ["target_selector"], "visibleConditionValues": {"target_selector": "manual"}, "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "1", "defaultValue": ""}, {"key": "expectations", "label": "Expectations", "type": "expectation", "mandatoryGroups": [], "mandatoryConditionFields": [], "mandatoryConditionValues": [], "visibleConditionFields": [], "visibleConditionValues": [], "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "n", "defaultValue": [], "predefinedExpectations": [{"expectation_type": "VULNERABILITY", "expectation_name": "Not vulnerable", "expectation_description": "", "expectation_score": 100, "expectation_expectation_group": false}]}, '
                        '{"key": "template", "label": "Manual template path (-t)", "type": "text", "mandatoryGroups": [], "mandatoryConditionFields": [], "mandatoryConditionValues": [], "visibleConditionFields": [], "visibleConditionValues": [], "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "1", "defaultValue": ["filepath_4"]}, '
                        '{"key": "options", "label": "Options", "type": "text", "mandatoryGroups": [], "mandatoryConditionFields": [], "mandatoryConditionValues": [], "visibleConditionFields": [], "visibleConditionValues": [], "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "1", "defaultValue": ""}], "outputs": [{"type": "cve", "field": "cve", "labels": ["nuclei"], "isFindingCompatible": true, "isMultiple": true}, {"type": "text", "field": "others", "labels": ["nuclei"], "isFindingCompatible": true, "isMultiple": true}], "config": {"type": "openaev_nuclei", "expose": true, "label": {"en": "Nuclei Scan", "fr": "Nuclei Scan"}, "color_dark": "#ff5722", "color_light": "#ff5722"}, "manual": false, "variables": [{"key": "user", "label": "User that will receive the injection", "type": "String", "cardinality": "1", "children": [{"key": "user.id", "label": "Id of the user in the platform", "type": "String", "cardinality": "1", "children": []}, {"key": "user.email", "label": "Email of the user", "type": "String", "cardinality": "1", "children": []}, {"key": "user.firstname", "label": "Firstname of the user", "type": "String", "cardinality": "1", "children": []}, {"key": "user.lastname", "label": "Lastname of the user", "type": "String", "cardinality": "1", "children": []}, {"key": "user.lang", "label": "Lang of the user", "type": "String", "cardinality": "1", "children": []}]}, {"key": "exercise", "label": "Exercise of the current injection", "type": "Object", "cardinality": "1", "children": [{"key": "exercise.id", "label": "Id of the exercise in the platform", "type": "String", "cardinality": "1", "children": []}, {"key": "exercise.name", "label": "Name of the exercise", "type": "String", "cardinality": "1", "children": []}, {"key": "exercise.description", "label": "Description of the exercise", "type": "String", "cardinality": "1", "children": []}]}, {"key": "teams", "label": "List of team name for the injection", "type": "String", "cardinality": "n", "children": []}, {"key": "player_uri", "label": "Player interface platform link", "type": "String", "cardinality": "1", "children": []}, {"key": "challenges_uri", "label": "Challenges interface platform link", "type": "String", "cardinality": "1", "children": []}, {"key": "scoreboard_uri", "label": "Scoreboard interface platform link", "type": "String", "cardinality": "1", "children": []}, {"key": "lessons_uri", "label": "Lessons learned interface platform link", "type": "String", "cardinality": "1", "children": []}], "contract_attack_patterns_external_ids": [], "contract_vulnerability_external_ids": ["CVE-0004-1131"], "is_atomic_testing": true, "platforms": [], "external_id": "external-injector-contract_'
                        + self.INJECTOR_ID
                        + '_CVE-0004-1131", "domains": [{"domain_name": "Network", "domain_color": "#009933"}]}',
                        "is_atomic_testing": True,
                        "contract_platforms": [],
                        "contract_domains": [
                            {"domain_name": "Network", "domain_color": "#009933"}
                        ],
                    },
                ),
                call(
                    "external-injector-contract_{}_CVE-0005-0519".format(
                        self.INJECTOR_ID
                    ),
                    {
                        "contract_manual": False,
                        "contract_labels": {
                            SupportedLanguage.en: "CVE-0005-0519",
                            SupportedLanguage.fr: "CVE-0005-0519",
                        },
                        "contract_attack_patterns_external_ids": [],
                        "contract_vulnerability_external_ids": ["CVE-0005-0519"],
                        "contract_content": '{"contract_id": "contract_to_keep_3", "label": {"en": "CVE-0005-0519", "fr": "CVE-0005-0519"}, "fields": [{"key": "target_selector", "label": "Type of targets", "type": "select", "mandatoryGroups": [], "mandatoryConditionFields": [], "mandatoryConditionValues": [], "visibleConditionFields": [], "visibleConditionValues": [], "linkedFields": [], "mandatory": true, "readOnly": false, "cardinality": "1", "defaultValue": ["asset-groups"], "choices": {"assets": "Assets", "manual": "Manual", "asset-groups": "Asset groups"}}, {"key": "assets", "label": "Targeted assets", "type": "asset", "mandatoryGroups": [], "mandatoryConditionFields": ["target_selector"], "mandatoryConditionValues": {"target_selector": "assets"}, "visibleConditionFields": ["target_selector"], "visibleConditionValues": {"target_selector": "assets"}, "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "n", "defaultValue": []}, {"key": "asset_groups", "label": "Targeted asset groups", "type": "asset-group", "mandatoryGroups": [], "mandatoryConditionFields": ["target_selector"], "mandatoryConditionValues": {"target_selector": "asset-groups"}, "visibleConditionFields": ["target_selector"], "visibleConditionValues": {"target_selector": "asset-groups"}, "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "n", "defaultValue": []}, {"key": "target_property_selector", "label": "Targeted assets property", "type": "select", "mandatoryGroups": [], "mandatoryConditionFields": ["target_selector"], "mandatoryConditionValues": {"target_selector": ["assets", "asset-groups"]}, "visibleConditionFields": ["target_selector"], "visibleConditionValues": {"target_selector": ["assets", "asset-groups"]}, "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "1", "defaultValue": ["automatic"], "choices": {"automatic": "Automatic", "hostname": "Hostname", "seen_ip": "Seen IP", "local_ip": "Local IP (first)"}}, {"key": "targets", "label": "Manual targets (comma-separated)", "type": "text", "mandatoryGroups": [], "mandatoryConditionFields": ["target_selector"], "mandatoryConditionValues": {"target_selector": "manual"}, "visibleConditionFields": ["target_selector"], "visibleConditionValues": {"target_selector": "manual"}, "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "1", "defaultValue": ""}, {"key": "expectations", "label": "Expectations", "type": "expectation", "mandatoryGroups": [], "mandatoryConditionFields": [], "mandatoryConditionValues": [], "visibleConditionFields": [], "visibleConditionValues": [], "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "n", "defaultValue": [], "predefinedExpectations": [{"expectation_type": "VULNERABILITY", "expectation_name": "Not vulnerable", "expectation_description": "", "expectation_score": 100, "expectation_expectation_group": false}]}, '
                        '{"key": "template", "label": "Manual template path (-t)", "type": "text", "mandatoryGroups": [], "mandatoryConditionFields": [], "mandatoryConditionValues": [], "visibleConditionFields": [], "visibleConditionValues": [], "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "1", "defaultValue": ["filepath_5"]}, '
                        '{"key": "options", "label": "Options", "type": "text", "mandatoryGroups": [], "mandatoryConditionFields": [], "mandatoryConditionValues": [], "visibleConditionFields": [], "visibleConditionValues": [], "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "1", "defaultValue": ""}], "outputs": [{"type": "cve", "field": "cve", "labels": ["nuclei"], "isFindingCompatible": true, "isMultiple": true}, {"type": "text", "field": "others", "labels": ["nuclei"], "isFindingCompatible": true, "isMultiple": true}], "config": {"type": "openaev_nuclei", "expose": true, "label": {"en": "Nuclei Scan", "fr": "Nuclei Scan"}, "color_dark": "#ff5722", "color_light": "#ff5722"}, "manual": false, "variables": [{"key": "user", "label": "User that will receive the injection", "type": "String", "cardinality": "1", "children": [{"key": "user.id", "label": "Id of the user in the platform", "type": "String", "cardinality": "1", "children": []}, {"key": "user.email", "label": "Email of the user", "type": "String", "cardinality": "1", "children": []}, {"key": "user.firstname", "label": "Firstname of the user", "type": "String", "cardinality": "1", "children": []}, {"key": "user.lastname", "label": "Lastname of the user", "type": "String", "cardinality": "1", "children": []}, {"key": "user.lang", "label": "Lang of the user", "type": "String", "cardinality": "1", "children": []}]}, {"key": "exercise", "label": "Exercise of the current injection", "type": "Object", "cardinality": "1", "children": [{"key": "exercise.id", "label": "Id of the exercise in the platform", "type": "String", "cardinality": "1", "children": []}, {"key": "exercise.name", "label": "Name of the exercise", "type": "String", "cardinality": "1", "children": []}, {"key": "exercise.description", "label": "Description of the exercise", "type": "String", "cardinality": "1", "children": []}]}, {"key": "teams", "label": "List of team name for the injection", "type": "String", "cardinality": "n", "children": []}, {"key": "player_uri", "label": "Player interface platform link", "type": "String", "cardinality": "1", "children": []}, {"key": "challenges_uri", "label": "Challenges interface platform link", "type": "String", "cardinality": "1", "children": []}, {"key": "scoreboard_uri", "label": "Scoreboard interface platform link", "type": "String", "cardinality": "1", "children": []}, {"key": "lessons_uri", "label": "Lessons learned interface platform link", "type": "String", "cardinality": "1", "children": []}], "contract_attack_patterns_external_ids": [], "contract_vulnerability_external_ids": ["CVE-0005-0519"], "is_atomic_testing": true, "platforms": [], "external_id": "external-injector-contract_'
                        + self.INJECTOR_ID
                        + '_CVE-0005-0519", "domains": [{"domain_name": "Network", "domain_color": "#009933"}]}',
                        "is_atomic_testing": True,
                        "contract_platforms": [],
                        "contract_domains": [
                            {"domain_name": "Network", "domain_color": "#009933"}
                        ],
                    },
                ),
            ]
        )

        self.assertEqual(len(mock_oaev_client.injector_contract.create.mock_calls), 3)
        mock_oaev_client.injector_contract.create.assert_has_calls(
            calls=[
                call(
                    {
                        "contract_id": generated_uuids[0],
                        "external_contract_id": "external-injector-contract_{}_CVE-0001-0114".format(
                            self.INJECTOR_ID
                        ),
                        "injector_id": self.INJECTOR_ID,
                        "contract_manual": False,
                        "contract_labels": {
                            SupportedLanguage.en: "CVE-0001-0114",
                            SupportedLanguage.fr: "CVE-0001-0114",
                        },
                        "contract_attack_patterns_external_ids": [],
                        "contract_vulnerability_external_ids": ["CVE-0001-0114"],
                        "contract_content": '{"contract_id": "'
                        + generated_uuids[0]
                        + '", "label": {"en": "CVE-0001-0114", "fr": "CVE-0001-0114"}, "fields": [{"key": "target_selector", "label": "Type of targets", "type": "select", "mandatoryGroups": [], "mandatoryConditionFields": [], "mandatoryConditionValues": [], "visibleConditionFields": [], "visibleConditionValues": [], "linkedFields": [], "mandatory": true, "readOnly": false, "cardinality": "1", "defaultValue": ["asset-groups"], "choices": {"assets": "Assets", "manual": "Manual", "asset-groups": "Asset groups"}}, {"key": "assets", "label": "Targeted assets", "type": "asset", "mandatoryGroups": [], "mandatoryConditionFields": ["target_selector"], "mandatoryConditionValues": {"target_selector": "assets"}, "visibleConditionFields": ["target_selector"], "visibleConditionValues": {"target_selector": "assets"}, "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "n", "defaultValue": []}, {"key": "asset_groups", "label": "Targeted asset groups", "type": "asset-group", "mandatoryGroups": [], "mandatoryConditionFields": ["target_selector"], "mandatoryConditionValues": {"target_selector": "asset-groups"}, "visibleConditionFields": ["target_selector"], "visibleConditionValues": {"target_selector": "asset-groups"}, "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "n", "defaultValue": []}, {"key": "target_property_selector", "label": "Targeted assets property", "type": "select", "mandatoryGroups": [], "mandatoryConditionFields": ["target_selector"], "mandatoryConditionValues": {"target_selector": ["assets", "asset-groups"]}, "visibleConditionFields": ["target_selector"], "visibleConditionValues": {"target_selector": ["assets", "asset-groups"]}, "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "1", "defaultValue": ["automatic"], "choices": {"automatic": "Automatic", "hostname": "Hostname", "seen_ip": "Seen IP", "local_ip": "Local IP (first)"}}, {"key": "targets", "label": "Manual targets (comma-separated)", "type": "text", "mandatoryGroups": [], "mandatoryConditionFields": ["target_selector"], "mandatoryConditionValues": {"target_selector": "manual"}, "visibleConditionFields": ["target_selector"], "visibleConditionValues": {"target_selector": "manual"}, "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "1", "defaultValue": ""}, {"key": "expectations", "label": "Expectations", "type": "expectation", "mandatoryGroups": [], "mandatoryConditionFields": [], "mandatoryConditionValues": [], "visibleConditionFields": [], "visibleConditionValues": [], "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "n", "defaultValue": [], "predefinedExpectations": [{"expectation_type": "VULNERABILITY", "expectation_name": "Not vulnerable", "expectation_description": "", "expectation_score": 100, "expectation_expectation_group": false}]}, '
                        '{"key": "template", "label": "Manual template path (-t)", "type": "text", "mandatoryGroups": [], "mandatoryConditionFields": [], "mandatoryConditionValues": [], "visibleConditionFields": [], "visibleConditionValues": [], "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "1", "defaultValue": ["filepath_1"]}, '
                        '{"key": "options", "label": "Options", "type": "text", "mandatoryGroups": [], "mandatoryConditionFields": [], "mandatoryConditionValues": [], "visibleConditionFields": [], "visibleConditionValues": [], "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "1", "defaultValue": ""}], "outputs": [{"type": "cve", "field": "cve", "labels": ["nuclei"], "isFindingCompatible": true, "isMultiple": true}, {"type": "text", "field": "others", "labels": ["nuclei"], "isFindingCompatible": true, "isMultiple": true}], "config": {"type": "openaev_nuclei", "expose": true, "label": {"en": "Nuclei Scan", "fr": "Nuclei Scan"}, "color_dark": "#ff5722", "color_light": "#ff5722"}, "manual": false, "variables": [{"key": "user", "label": "User that will receive the injection", "type": "String", "cardinality": "1", "children": [{"key": "user.id", "label": "Id of the user in the platform", "type": "String", "cardinality": "1", "children": []}, {"key": "user.email", "label": "Email of the user", "type": "String", "cardinality": "1", "children": []}, {"key": "user.firstname", "label": "Firstname of the user", "type": "String", "cardinality": "1", "children": []}, {"key": "user.lastname", "label": "Lastname of the user", "type": "String", "cardinality": "1", "children": []}, {"key": "user.lang", "label": "Lang of the user", "type": "String", "cardinality": "1", "children": []}]}, {"key": "exercise", "label": "Exercise of the current injection", "type": "Object", "cardinality": "1", "children": [{"key": "exercise.id", "label": "Id of the exercise in the platform", "type": "String", "cardinality": "1", "children": []}, {"key": "exercise.name", "label": "Name of the exercise", "type": "String", "cardinality": "1", "children": []}, {"key": "exercise.description", "label": "Description of the exercise", "type": "String", "cardinality": "1", "children": []}]}, {"key": "teams", "label": "List of team name for the injection", "type": "String", "cardinality": "n", "children": []}, {"key": "player_uri", "label": "Player interface platform link", "type": "String", "cardinality": "1", "children": []}, {"key": "challenges_uri", "label": "Challenges interface platform link", "type": "String", "cardinality": "1", "children": []}, {"key": "scoreboard_uri", "label": "Scoreboard interface platform link", "type": "String", "cardinality": "1", "children": []}, {"key": "lessons_uri", "label": "Lessons learned interface platform link", "type": "String", "cardinality": "1", "children": []}], "contract_attack_patterns_external_ids": [], "contract_vulnerability_external_ids": ["CVE-0001-0114"], "is_atomic_testing": true, "platforms": [], "external_id": "external-injector-contract_'
                        + self.INJECTOR_ID
                        + '_CVE-0001-0114", "domains": [{"domain_name": "Network", "domain_color": "#009933"}]}',
                        "is_atomic_testing": True,
                        "contract_platforms": [],
                        "contract_domains": [
                            {"domain_name": "Network", "domain_color": "#009933"}
                        ],
                    }
                ),
                call(
                    {
                        "contract_id": generated_uuids[1],
                        "external_contract_id": "external-injector-contract_{}_CVE-0002-0760".format(
                            self.INJECTOR_ID
                        ),
                        "injector_id": self.INJECTOR_ID,
                        "contract_manual": False,
                        "contract_labels": {
                            SupportedLanguage.en: "CVE-0002-0760",
                            SupportedLanguage.fr: "CVE-0002-0760",
                        },
                        "contract_attack_patterns_external_ids": [],
                        "contract_vulnerability_external_ids": ["CVE-0002-0760"],
                        "contract_content": '{"contract_id": "'
                        + generated_uuids[1]
                        + '", "label": {"en": "CVE-0002-0760", "fr": "CVE-0002-0760"}, "fields": [{"key": "target_selector", "label": "Type of targets", "type": "select", "mandatoryGroups": [], "mandatoryConditionFields": [], "mandatoryConditionValues": [], "visibleConditionFields": [], "visibleConditionValues": [], "linkedFields": [], "mandatory": true, "readOnly": false, "cardinality": "1", "defaultValue": ["asset-groups"], "choices": {"assets": "Assets", "manual": "Manual", "asset-groups": "Asset groups"}}, {"key": "assets", "label": "Targeted assets", "type": "asset", "mandatoryGroups": [], "mandatoryConditionFields": ["target_selector"], "mandatoryConditionValues": {"target_selector": "assets"}, "visibleConditionFields": ["target_selector"], "visibleConditionValues": {"target_selector": "assets"}, "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "n", "defaultValue": []}, {"key": "asset_groups", "label": "Targeted asset groups", "type": "asset-group", "mandatoryGroups": [], "mandatoryConditionFields": ["target_selector"], "mandatoryConditionValues": {"target_selector": "asset-groups"}, "visibleConditionFields": ["target_selector"], "visibleConditionValues": {"target_selector": "asset-groups"}, "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "n", "defaultValue": []}, {"key": "target_property_selector", "label": "Targeted assets property", "type": "select", "mandatoryGroups": [], "mandatoryConditionFields": ["target_selector"], "mandatoryConditionValues": {"target_selector": ["assets", "asset-groups"]}, "visibleConditionFields": ["target_selector"], "visibleConditionValues": {"target_selector": ["assets", "asset-groups"]}, "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "1", "defaultValue": ["automatic"], "choices": {"automatic": "Automatic", "hostname": "Hostname", "seen_ip": "Seen IP", "local_ip": "Local IP (first)"}}, {"key": "targets", "label": "Manual targets (comma-separated)", "type": "text", "mandatoryGroups": [], "mandatoryConditionFields": ["target_selector"], "mandatoryConditionValues": {"target_selector": "manual"}, "visibleConditionFields": ["target_selector"], "visibleConditionValues": {"target_selector": "manual"}, "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "1", "defaultValue": ""}, {"key": "expectations", "label": "Expectations", "type": "expectation", "mandatoryGroups": [], "mandatoryConditionFields": [], "mandatoryConditionValues": [], "visibleConditionFields": [], "visibleConditionValues": [], "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "n", "defaultValue": [], "predefinedExpectations": [{"expectation_type": "VULNERABILITY", "expectation_name": "Not vulnerable", "expectation_description": "", "expectation_score": 100, "expectation_expectation_group": false}]}, '
                        '{"key": "template", "label": "Manual template path (-t)", "type": "text", "mandatoryGroups": [], "mandatoryConditionFields": [], "mandatoryConditionValues": [], "visibleConditionFields": [], "visibleConditionValues": [], "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "1", "defaultValue": ["filepath_2"]}, '
                        '{"key": "options", "label": "Options", "type": "text", "mandatoryGroups": [], "mandatoryConditionFields": [], "mandatoryConditionValues": [], "visibleConditionFields": [], "visibleConditionValues": [], "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "1", "defaultValue": ""}], "outputs": [{"type": "cve", "field": "cve", "labels": ["nuclei"], "isFindingCompatible": true, "isMultiple": true}, {"type": "text", "field": "others", "labels": ["nuclei"], "isFindingCompatible": true, "isMultiple": true}], "config": {"type": "openaev_nuclei", "expose": true, "label": {"en": "Nuclei Scan", "fr": "Nuclei Scan"}, "color_dark": "#ff5722", "color_light": "#ff5722"}, "manual": false, "variables": [{"key": "user", "label": "User that will receive the injection", "type": "String", "cardinality": "1", "children": [{"key": "user.id", "label": "Id of the user in the platform", "type": "String", "cardinality": "1", "children": []}, {"key": "user.email", "label": "Email of the user", "type": "String", "cardinality": "1", "children": []}, {"key": "user.firstname", "label": "Firstname of the user", "type": "String", "cardinality": "1", "children": []}, {"key": "user.lastname", "label": "Lastname of the user", "type": "String", "cardinality": "1", "children": []}, {"key": "user.lang", "label": "Lang of the user", "type": "String", "cardinality": "1", "children": []}]}, {"key": "exercise", "label": "Exercise of the current injection", "type": "Object", "cardinality": "1", "children": [{"key": "exercise.id", "label": "Id of the exercise in the platform", "type": "String", "cardinality": "1", "children": []}, {"key": "exercise.name", "label": "Name of the exercise", "type": "String", "cardinality": "1", "children": []}, {"key": "exercise.description", "label": "Description of the exercise", "type": "String", "cardinality": "1", "children": []}]}, {"key": "teams", "label": "List of team name for the injection", "type": "String", "cardinality": "n", "children": []}, {"key": "player_uri", "label": "Player interface platform link", "type": "String", "cardinality": "1", "children": []}, {"key": "challenges_uri", "label": "Challenges interface platform link", "type": "String", "cardinality": "1", "children": []}, {"key": "scoreboard_uri", "label": "Scoreboard interface platform link", "type": "String", "cardinality": "1", "children": []}, {"key": "lessons_uri", "label": "Lessons learned interface platform link", "type": "String", "cardinality": "1", "children": []}], "contract_attack_patterns_external_ids": [], "contract_vulnerability_external_ids": ["CVE-0002-0760"], "is_atomic_testing": true, "platforms": [], "external_id": "external-injector-contract_'
                        + self.INJECTOR_ID
                        + '_CVE-0002-0760", "domains": [{"domain_name": "Network", "domain_color": "#009933"}]}',
                        "is_atomic_testing": True,
                        "contract_platforms": [],
                        "contract_domains": [
                            {"domain_name": "Network", "domain_color": "#009933"}
                        ],
                    }
                ),
                call(
                    {
                        "contract_id": generated_uuids[2],
                        "external_contract_id": "external-injector-contract_{}_CVE-0003-0537".format(
                            self.INJECTOR_ID
                        ),
                        "injector_id": self.INJECTOR_ID,
                        "contract_manual": False,
                        "contract_labels": {
                            SupportedLanguage.en: "CVE-0003-0537",
                            SupportedLanguage.fr: "CVE-0003-0537",
                        },
                        "contract_attack_patterns_external_ids": [],
                        "contract_vulnerability_external_ids": ["CVE-0003-0537"],
                        "contract_content": '{"contract_id": "'
                        + generated_uuids[2]
                        + '", "label": {"en": "CVE-0003-0537", "fr": "CVE-0003-0537"}, "fields": [{"key": "target_selector", "label": "Type of targets", "type": "select", "mandatoryGroups": [], "mandatoryConditionFields": [], "mandatoryConditionValues": [], "visibleConditionFields": [], "visibleConditionValues": [], "linkedFields": [], "mandatory": true, "readOnly": false, "cardinality": "1", "defaultValue": ["asset-groups"], "choices": {"assets": "Assets", "manual": "Manual", "asset-groups": "Asset groups"}}, {"key": "assets", "label": "Targeted assets", "type": "asset", "mandatoryGroups": [], "mandatoryConditionFields": ["target_selector"], "mandatoryConditionValues": {"target_selector": "assets"}, "visibleConditionFields": ["target_selector"], "visibleConditionValues": {"target_selector": "assets"}, "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "n", "defaultValue": []}, {"key": "asset_groups", "label": "Targeted asset groups", "type": "asset-group", "mandatoryGroups": [], "mandatoryConditionFields": ["target_selector"], "mandatoryConditionValues": {"target_selector": "asset-groups"}, "visibleConditionFields": ["target_selector"], "visibleConditionValues": {"target_selector": "asset-groups"}, "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "n", "defaultValue": []}, {"key": "target_property_selector", "label": "Targeted assets property", "type": "select", "mandatoryGroups": [], "mandatoryConditionFields": ["target_selector"], "mandatoryConditionValues": {"target_selector": ["assets", "asset-groups"]}, "visibleConditionFields": ["target_selector"], "visibleConditionValues": {"target_selector": ["assets", "asset-groups"]}, "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "1", "defaultValue": ["automatic"], "choices": {"automatic": "Automatic", "hostname": "Hostname", "seen_ip": "Seen IP", "local_ip": "Local IP (first)"}}, {"key": "targets", "label": "Manual targets (comma-separated)", "type": "text", "mandatoryGroups": [], "mandatoryConditionFields": ["target_selector"], "mandatoryConditionValues": {"target_selector": "manual"}, "visibleConditionFields": ["target_selector"], "visibleConditionValues": {"target_selector": "manual"}, "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "1", "defaultValue": ""}, {"key": "expectations", "label": "Expectations", "type": "expectation", "mandatoryGroups": [], "mandatoryConditionFields": [], "mandatoryConditionValues": [], "visibleConditionFields": [], "visibleConditionValues": [], "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "n", "defaultValue": [], "predefinedExpectations": [{"expectation_type": "VULNERABILITY", "expectation_name": "Not vulnerable", "expectation_description": "", "expectation_score": 100, "expectation_expectation_group": false}]}, '
                        '{"key": "template", "label": "Manual template path (-t)", "type": "text", "mandatoryGroups": [], "mandatoryConditionFields": [], "mandatoryConditionValues": [], "visibleConditionFields": [], "visibleConditionValues": [], "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "1", "defaultValue": ["filepath_3"]}, '
                        '{"key": "options", "label": "Options", "type": "text", "mandatoryGroups": [], "mandatoryConditionFields": [], "mandatoryConditionValues": [], "visibleConditionFields": [], "visibleConditionValues": [], "linkedFields": [], "mandatory": false, "readOnly": false, "cardinality": "1", "defaultValue": ""}], "outputs": [{"type": "cve", "field": "cve", "labels": ["nuclei"], "isFindingCompatible": true, "isMultiple": true}, {"type": "text", "field": "others", "labels": ["nuclei"], "isFindingCompatible": true, "isMultiple": true}], "config": {"type": "openaev_nuclei", "expose": true, "label": {"en": "Nuclei Scan", "fr": "Nuclei Scan"}, "color_dark": "#ff5722", "color_light": "#ff5722"}, "manual": false, "variables": [{"key": "user", "label": "User that will receive the injection", "type": "String", "cardinality": "1", "children": [{"key": "user.id", "label": "Id of the user in the platform", "type": "String", "cardinality": "1", "children": []}, {"key": "user.email", "label": "Email of the user", "type": "String", "cardinality": "1", "children": []}, {"key": "user.firstname", "label": "Firstname of the user", "type": "String", "cardinality": "1", "children": []}, {"key": "user.lastname", "label": "Lastname of the user", "type": "String", "cardinality": "1", "children": []}, {"key": "user.lang", "label": "Lang of the user", "type": "String", "cardinality": "1", "children": []}]}, {"key": "exercise", "label": "Exercise of the current injection", "type": "Object", "cardinality": "1", "children": [{"key": "exercise.id", "label": "Id of the exercise in the platform", "type": "String", "cardinality": "1", "children": []}, {"key": "exercise.name", "label": "Name of the exercise", "type": "String", "cardinality": "1", "children": []}, {"key": "exercise.description", "label": "Description of the exercise", "type": "String", "cardinality": "1", "children": []}]}, {"key": "teams", "label": "List of team name for the injection", "type": "String", "cardinality": "n", "children": []}, {"key": "player_uri", "label": "Player interface platform link", "type": "String", "cardinality": "1", "children": []}, {"key": "challenges_uri", "label": "Challenges interface platform link", "type": "String", "cardinality": "1", "children": []}, {"key": "scoreboard_uri", "label": "Scoreboard interface platform link", "type": "String", "cardinality": "1", "children": []}, {"key": "lessons_uri", "label": "Lessons learned interface platform link", "type": "String", "cardinality": "1", "children": []}], "contract_attack_patterns_external_ids": [], "contract_vulnerability_external_ids": ["CVE-0003-0537"], "is_atomic_testing": true, "platforms": [], "external_id": "external-injector-contract_'
                        + self.INJECTOR_ID
                        + '_CVE-0003-0537", "domains": [{"domain_name": "Network", "domain_color": "#009933"}]}',
                        "is_atomic_testing": True,
                        "contract_platforms": [],
                        "contract_domains": [
                            {"domain_name": "Network", "domain_color": "#009933"}
                        ],
                    }
                ),
            ]
        )
