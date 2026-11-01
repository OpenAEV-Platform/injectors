Feature: SMTP email delivery
  As the Email (SMTP) injector
  I want to build and deliver MIME emails over SMTP
  So that crafted emails reach their recipients safely

  Scenario: Sending an authenticated TLS email
    Given valid SMTP credentials and TLS enabled
    When the email is sent
    Then STARTTLS and login are performed
    And the envelope sender and recipients are set correctly
    And the connection is closed

  Scenario: Sending an unauthenticated plain email
    Given no credentials and TLS disabled
    When the email is sent
    Then STARTTLS and login are skipped
    And the message is delivered

  Scenario: Rejecting incomplete credentials
    Given a username without a password
    When the email is sent
    Then no SMTP connection is opened
    And an error explains both credentials are required

  Scenario: Attaching one or more files
    Given attachments are provided
    When the email is sent
    Then each attachment appears as a MIME part

  Scenario: Closing the connection when sending fails
    Given the SMTP server raises during send
    When the email is sent
    Then the failure is reported
    And the connection is closed

  Scenario: Rejecting header injection in recipient or subject
    Given a recipient or subject containing CRLF header injection
    When the email is sent
    Then the message is rejected as a failure

  Scenario: Reporting connection failures
    Given the SMTP server is unreachable
    When the email is sent
    Then the failure is reported
