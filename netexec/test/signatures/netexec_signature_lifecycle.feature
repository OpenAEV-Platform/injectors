Feature: Netexec signature lifecycle
    As the OpenAEV platform
    I want the Netexec injector to compile and send ExpectationSignature structured output
    So that execution evidence is recorded and linked to the correct targets and expectations

    Background:
        Given a Netexec injector instance

    Scenario: Pre-execution signatures are compiled before running NetExec
        Given an inject with a single IPv4 target "10.0.0.1"
        When process_message is called
        Then compile_pre_execution_signatures is called with a NetworkInjectorConfig for "10.0.0.1"

    Scenario: Post-execution signatures are compiled after a successful run
        Given an inject with a single IPv4 target "10.0.0.1"
        And NetExec exits with return code 0
        When process_message is called
        Then compile_post_execution_signatures is called with execution_status "success"

    Scenario: Post-execution signatures reflect a failed run
        Given an inject with a single IPv4 target "10.0.0.1"
        And NetExec exits with return code 1
        When process_message is called
        Then compile_post_execution_signatures is called with a non-zero exit code

    Scenario: Signatures are sent after a successful execution
        Given an inject with a single IPv4 target "10.0.0.1"
        And NetExec exits with return code 0
        When process_message is called
        Then send_signatures is called with the inject id and phase "execution_complete"

    Scenario: Signatures are sent even after a failed execution
        Given an inject with a single IPv4 target "10.0.0.1"
        And NetExec exits with return code 1
        When process_message is called
        Then send_signatures is called with the inject id and phase "execution_complete"

    Scenario: Each target gets its own signature config
        Given an inject with targets "10.0.0.1" and "192.168.1.1"
        When process_message is called
        Then compile_pre_execution_signatures is called with 2 NetworkInjectorConfig entries

    Scenario: Asset metadata is mapped to signature target
        Given an inject with target "10.0.0.1" mapped to asset id "asset-abc-123"
        When process_message is called
        Then build_payload is called with target meta containing asset "asset-abc-123"

    Scenario Outline: Netexec signature types are always network-category types
        Given the netexec signature helper
        Then NETEXEC_SIGNATURE_TYPES contains "<sig_type>"

        Examples:
            | sig_type                 |
            | source_ipv4_address      |
            | target_ipv4_address      |
            | target_ipv6_address      |
            | target_hostname_address  |
            | start_date               |
            | end_date                 |
