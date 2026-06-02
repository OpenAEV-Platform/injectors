Feature: ExpectationSignature output element in all Netexec contracts
    As the OpenAEV backend
    I want every Netexec contract to declare an ExpectationSignature output element
    So that the backend can route structured signature data to the correct processor

    Scenario: Base protocol contracts include ExpectationSignature output
        Given the Netexec base contracts are built
        Then each contract's outputs include an ExpectationSignature element

    Scenario: Option contracts include ExpectationSignature output
        Given the Netexec option contracts are built
        Then each contract's outputs include an ExpectationSignature element

    Scenario: Module contracts include ExpectationSignature output
        Given the Netexec module contracts are built
        Then each contract's outputs include an ExpectationSignature element

    Scenario: build_outputs_for_types always includes ExpectationSignature
        Given any set of output types
        When build_outputs_for_types is called
        Then the result always contains an ExpectationSignature element

    Scenario Outline: ExpectationSignature is present even for no-output option contracts
        Given an option contract with id "<option_id>"
        When the option contract outputs are built
        Then the outputs include an ExpectationSignature element

        Examples:
            | option_id   |
            | local_auth  |
            | no_output   |
            | screenshot  |
