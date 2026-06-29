"""Tests for ExpectationSignature output element presence in all Netexec contracts.

Gherkin: test/contracts/expectation_signature_output.feature
"""

from unittest import TestCase
from unittest.mock import patch

from netexec.contracts import contract_outputs as co
from netexec.contracts.contract_outputs import (
    _EXPECTATION_SIGNATURE_OUTPUT,
    build_outputs_for_types,
)
from netexec.contracts.output_registry import (
    EXPECTATION_SIGNATURE,
    get_base_output_types,
    get_module_output_types,
    get_option_output_types,
)


def _call_and_capture(output_types: set) -> list:
    """Call build_outputs_for_types and return the element list passed to add_outputs."""
    with patch.object(co, "ContractBuilder") as mock_cb:
        mock_cb.return_value.add_outputs.return_value = mock_cb.return_value
        mock_cb.return_value.build_outputs.return_value = []
        build_outputs_for_types(output_types)
        return mock_cb.return_value.add_outputs.call_args[0][0]


class ExpectationSignatureOutputTest(TestCase):

    # -- Scenario: build_outputs_for_types always includes ExpectationSignature --

    def test_empty_output_types_still_yields_expectation_signature(self):
        """
        Given an empty set of output types
        When build_outputs_for_types is called
        Then the elements passed to ContractBuilder contain exactly the ExpectationSignature
        """
        elements = _call_and_capture(set())
        self.assertEqual(elements, [_EXPECTATION_SIGNATURE_OUTPUT])

    def test_text_output_includes_expectation_signature_appended(self):
        """
        Given output types {"text"}
        When build_outputs_for_types is called
        Then ExpectationSignature is the last element in the built list
        """
        elements = _call_and_capture({"text"})
        self.assertGreater(len(elements), 1)
        self.assertIs(elements[-1], _EXPECTATION_SIGNATURE_OUTPUT)

    def test_multiple_output_types_always_end_with_expectation_signature(self):
        """
        Given multiple output types
        When build_outputs_for_types is called
        Then the last element is always _EXPECTATION_SIGNATURE_OUTPUT
        """
        from netexec.contracts.output_registry import (
            CREDENTIALS,
            SHARE,
            TEXT,
            USERNAME,
        )

        elements = _call_and_capture({TEXT, CREDENTIALS, USERNAME, SHARE})
        self.assertIs(elements[-1], _EXPECTATION_SIGNATURE_OUTPUT)
        # 4 typed outputs + 1 expectation_signature
        self.assertEqual(len(elements), 5)

    # -- Scenario: base contracts include ExpectationSignature --

    def test_base_output_types_include_expectation_signature(self):
        """
        Given the Netexec base output types
        When build_outputs_for_types is called
        Then ExpectationSignature is appended
        """
        elements = _call_and_capture(get_base_output_types())
        self.assertIs(elements[-1], _EXPECTATION_SIGNATURE_OUTPUT)
        # base = {TEXT} → 2 elements
        self.assertEqual(len(elements), 2)

    # -- Scenario: option contracts include ExpectationSignature --

    def test_option_shares_output_includes_expectation_signature(self):
        """
        Given the 'shares' option contract output types
        When build_outputs_for_types is called
        Then ExpectationSignature is appended
        """
        elements = _call_and_capture(get_option_output_types("shares"))
        self.assertIs(elements[-1], _EXPECTATION_SIGNATURE_OUTPUT)

    def test_no_output_option_includes_expectation_signature(self):
        """
        Given a no-output option contract (e.g. 'local_auth')
        When build_outputs_for_types is called
        Then ExpectationSignature is still the only element

        Scenario: ExpectationSignature is present even for no-output option contracts
        """
        for option_id in ("local_auth", "no_output", "screenshot"):
            with self.subTest(option_id=option_id):
                opt_types = get_option_output_types(option_id)
                self.assertEqual(opt_types, set())
                elements = _call_and_capture(opt_types)
                self.assertEqual(elements, [_EXPECTATION_SIGNATURE_OUTPUT])

    # -- Scenario: module contracts include ExpectationSignature --

    def test_module_lsassy_output_includes_expectation_signature(self):
        """
        Given the 'lsassy' module contract output types
        When build_outputs_for_types is called
        Then ExpectationSignature is appended
        """
        elements = _call_and_capture(get_module_output_types("lsassy"))
        self.assertIs(elements[-1], _EXPECTATION_SIGNATURE_OUTPUT)

    # -- EXPECTATION_SIGNATURE constant --

    def test_expectation_signature_constant(self):
        """
        Given the output registry
        Then EXPECTATION_SIGNATURE equals 'expectation_signatures'
        """
        self.assertEqual(EXPECTATION_SIGNATURE, "expectation_signatures")
