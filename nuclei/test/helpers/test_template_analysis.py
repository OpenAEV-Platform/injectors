import os
import tempfile
import unittest
from unittest.mock import MagicMock

import yaml
from pyoaev.credential.resolved import UsernamePasswordSecret

from nuclei.helpers.nuclei_command_builder import NucleiCommandBuilder
from nuclei.helpers.template_analysis import (
    analyze_template,
    analyze_template_file,
    resolve_template_path,
)
from nuclei.helpers.template_inputs import (
    MissingTemplateInputs,
    TemplateNotFound,
    check_templates_exist,
    collect_template_variables,
    redact_args,
)

# Shape of http/cves/2024/CVE-2024-9264.yaml: a login with {{username}} and
# {{password}}, a session cookie, then the file-read query.
AUTHENTICATED_TEMPLATE = """
id: CVE-2024-9264
info:
  name: Authenticated file read
  severity: high
  description: |
    The application allows file reads through its query endpoint. The attacker
    must be authenticated with Viewer permissions or higher.
  tags: cve,cve2024,authenticated,lfi
http:
  - raw:
      - |
        POST /login HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/json

        {"user":"{{username}}","password":"{{password}}"}
      - |
        POST /api/ds/query HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/json

        {"queries":[{"expression":"SELECT content FROM read_blob('/etc/passwd')"}]}
    matchers:
      - type: dsl
        internal: true
        dsl:
          - contains(header_1, "session")
      - type: regex
        regex:
          - "root:.*:0:0:"
"""

# A version check: GET only, no operator value.
READ_ONLY_TEMPLATE = """
id: CVE-0000-0001
info:
  name: Version detection
  severity: info
  tags: cve,tech
http:
  - method: GET
    path:
      - "{{BaseURL}}/api/health"
    extractors:
      - type: regex
        name: version
        regex:
          - '"version":"([0-9.]+)"'
    matchers:
      - type: word
        words:
          - "{{version}}"
"""

# Shape of http/cves/2020/CVE-2020-11978.yaml: state-changing POSTs that trigger
# a job on the target.
INTRUSIVE_TEMPLATE = """
id: CVE-2020-11978
info:
  name: Command injection through an example job
  severity: high
  tags: cve,cve2020,rce
http:
  - raw:
      - |
        GET /api/experimental/test HTTP/1.1
        Host: {{Hostname}}
      - |
        POST /api/experimental/dags/example/dag_runs HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/json

        {"conf": {"message": "\\"; touch test #"}}
    matchers:
      - type: word
        words:
          - "{{randstr}}"
"""

OPERATOR_VARIABLE_TEMPLATE = """
id: CVE-0000-0002
info:
  name: Token-protected endpoint
  severity: medium
  tags: cve
variables:
  marker: "{{rand_base(6)}}"
http:
  - method: GET
    path:
      - "{{BaseURL}}/api/items?token={{api_token}}&m={{marker}}"
"""


def _load(text):
    return analyze_template(yaml.safe_load(text))


class TemplateAnalysisTest(unittest.TestCase):
    def test_authenticated_template_needs_credentials(self):
        analysis = _load(AUTHENTICATED_TEMPLATE)
        self.assertEqual(analysis.variables, ["username", "password"])
        self.assertTrue(analysis.authenticated)
        self.assertTrue(analysis.needs_credentials)
        # The login is a POST: state-changing, so not read-only.
        self.assertTrue(analysis.intrusive)
        self.assertEqual(
            analysis.prerequisites,
            [
                "The attacker must be authenticated with Viewer permissions or "
                "higher."
            ],
        )

    def test_read_only_template_needs_nothing(self):
        analysis = _load(READ_ONLY_TEMPLATE)
        self.assertEqual(analysis.variables, [])
        self.assertFalse(analysis.authenticated)
        self.assertFalse(analysis.intrusive)
        self.assertTrue(analysis.read_only)
        metadata = analysis.to_metadata()
        self.assertEqual(metadata["read_only"], True)
        self.assertEqual(metadata["required_variables"], [])

    def test_state_changing_exploit_is_intrusive(self):
        analysis = _load(INTRUSIVE_TEMPLATE)
        self.assertTrue(analysis.intrusive)
        self.assertFalse(analysis.authenticated)
        self.assertEqual(analysis.variables, [])

    def test_intrusive_from_tags_and_protocols(self):
        self.assertTrue(
            analyze_template({"info": {"tags": "dos"}, "http": []}).intrusive
        )
        self.assertTrue(analyze_template({"info": {}, "code": [{}]}).intrusive)

    def test_operator_variable_without_template_defined_ones(self):
        analysis = _load(OPERATOR_VARIABLE_TEMPLATE)
        self.assertEqual(analysis.variables, ["api_token"])
        self.assertFalse(analysis.needs_credentials)

    def test_tagged_authenticated_without_placeholder_asks_credentials(self):
        analysis = analyze_template(
            {
                "info": {"tags": ["authenticated"]},
                "http": [{"method": "GET", "path": ["{{BaseURL}}/"]}],
            }
        )
        self.assertEqual(analysis.variables, ["username", "password"])

    def test_analyze_template_file_and_resolve_path(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "t.yaml")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(AUTHENTICATED_TEMPLATE)
            self.assertEqual(resolve_template_path(path), path)
            self.assertTrue(analyze_template_file(path).authenticated)
            os.environ["NUCLEI_TEMPLATES_DIR"] = directory
            try:
                self.assertEqual(resolve_template_path("t.yaml"), path)
            finally:
                del os.environ["NUCLEI_TEMPLATES_DIR"]
        self.assertIsNone(resolve_template_path(None))
        self.assertIsNone(resolve_template_path("/no/such/template.yaml"))
        self.assertIsNone(analyze_template_file(None))


class TemplateInputsTest(unittest.TestCase):
    def test_missing_credentials_raise_not_executed(self):
        analysis = _load(AUTHENTICATED_TEMPLATE)
        with self.assertRaises(MissingTemplateInputs) as raised:
            collect_template_variables(analysis, {}, lambda: None)
        self.assertEqual(raised.exception.missing, ["username", "password"])
        self.assertIn("inconclusive", str(raised.exception))
        self.assertIn("missing credentials", str(raised.exception))

    def test_credentials_from_the_attached_secret(self):
        analysis = _load(AUTHENTICATED_TEMPLATE)
        values = collect_template_variables(
            analysis,
            {},
            lambda: UsernamePasswordSecret(username="viewer", password="s3cret"),
        )
        self.assertEqual(values, {"username": "viewer", "password": "s3cret"})

    def test_operator_variable_from_the_contract_field(self):
        analysis = _load(OPERATOR_VARIABLE_TEMPLATE)
        resolver = MagicMock()
        self.assertEqual(
            collect_template_variables(analysis, {"var_api_token": " abc "}, resolver),
            {"api_token": "abc"},
        )
        resolver.assert_not_called()
        with self.assertRaises(MissingTemplateInputs):
            collect_template_variables(analysis, {"var_api_token": ""}, resolver)

    def test_template_without_variables_needs_nothing(self):
        self.assertEqual(
            collect_template_variables(_load(READ_ONLY_TEMPLATE), {}, MagicMock()), {}
        )
        self.assertEqual(collect_template_variables(None, {}, MagicMock()), {})

    def test_variables_reach_nuclei_and_secrets_are_redacted(self):
        configs = MagicMock()
        configs.exclude_type = []
        configs.exclude_severity = []
        args = NucleiCommandBuilder(
            configs,
            "contract",
            {"template": "t.yaml"},
            ["10.0.0.1"],
            variables={"username": "viewer", "password": "s3cret"},
        ).build()
        self.assertIn("username=viewer", args)
        self.assertIn("password=s3cret", args)
        self.assertEqual(args[args.index("password=s3cret") - 1], "-var")
        shown = redact_args(args)
        self.assertIn("password=***", shown)
        self.assertIn("username=viewer", shown)
        self.assertNotIn("password=s3cret", shown)


class TemplateNotFoundTest(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.directory = self._dir.name
        os.makedirs(os.path.join(self.directory, "http", "cves", "2024"))
        self.path = os.path.join("http", "cves", "2024", "CVE-2024-9264.yaml")
        with open(
            os.path.join(self.directory, self.path), "w", encoding="utf-8"
        ) as handle:
            handle.write(AUTHENTICATED_TEMPLATE)

    def tearDown(self):
        self._dir.cleanup()

    def test_known_template_and_id_pass(self):
        check_templates_exist(
            {"template": self.path, "options": "-id CVE-2024-9264"}, self.directory
        )

    def test_unknown_id_is_reported_per_id(self):
        with self.assertRaises(TemplateNotFound) as raised:
            check_templates_exist(
                {"options": "-id CVE-2024-9264,CVE-2023-28434 -id=CVE-1999-0001"},
                self.directory,
            )
        self.assertEqual(raised.exception.missing, ["CVE-2023-28434", "CVE-1999-0001"])
        self.assertIn("Not executed: template not found", str(raised.exception))

    def test_unknown_template_path_is_reported(self):
        with self.assertRaises(TemplateNotFound) as raised:
            check_templates_exist(
                {"template": "http/cves/2023/CVE-2023-28434.yaml"}, self.directory
            )
        self.assertEqual(
            raised.exception.missing, ["http/cves/2023/CVE-2023-28434.yaml"]
        )

    def test_directories_globs_and_absent_template_set_are_left_to_nuclei(self):
        check_templates_exist(
            {"options": "-t http/cves/ -id 'CVE-2023-*'"}, self.directory
        )
        check_templates_exist(
            {"template": "missing.yaml"}, os.path.join(self.directory, "absent")
        )


if __name__ == "__main__":
    unittest.main()
