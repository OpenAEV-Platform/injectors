Feature: Craft email contract execution
  As the Email (SMTP) injector
  I want to execute the craft-email contract
  So that emails are crafted, attachments delivered, and results reported

  Scenario: Rejecting an unsupported contract
    Given an inject referencing another contract
    When execute is called
    Then an unsupported-contract error is raised

  Scenario: Sending an email with downloaded attachments
    Given an inject with an attached document
    When execute is called
    Then the document is downloaded from the API
    And it is passed to the SMTP client as an attachment

  Scenario: Requiring a document id for attachments
    Given an attached document without a document_id
    When extracting attachments
    Then a missing-field error is raised

  Scenario: Reporting execution status back to the platform
    Given the SMTP client reports a failure
    When the message is processed
    Then the reception is acknowledged
    And the callback reports an ERROR status with the failure message
