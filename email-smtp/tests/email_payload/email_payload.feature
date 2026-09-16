Feature: Email payload building
  As the Email (SMTP) injector
  I want to normalize inject content into a mail payload
  So that downstream SMTP delivery receives clean values

  Scenario: Building a full payload
    Given inject content with all fields populated
    When the payload is built
    Then port is coerced to an integer
    And cc and bcc are parsed into lists
    And all values are preserved

  Scenario: Applying defaults for optional fields
    Given inject content with only mandatory fields
    When the payload is built
    Then TLS defaults to disabled
    And credentials default to none
    And mail_from falls back to the from address
    And cc and bcc default to empty lists

  Scenario: Falling back mail_from when empty
    Given an empty mail_from value
    When the payload is built
    Then mail_from falls back to the from address

  Scenario: Treating whitespace optional emails as omitted
    Given whitespace-only mail_from and reply_to
    When the payload is built
    Then mail_from falls back to the from address
    And reply_to is none

  Scenario: Stripping optional emails
    Given padded mail_from and reply_to values
    When the payload is built
    Then the values are stripped

  Scenario: Parsing boolean TLS from strings
    Given a string TLS value
    When the payload is built
    Then it is coerced to a boolean
