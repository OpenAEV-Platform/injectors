Feature: Prowler multi-provider form input
  An OpenAEV form submission selects exactly one supported Prowler provider and
  keeps provider credentials out of ordinary serialized output.

  Scenario Outline: Select one supported provider input
    Given a complete "<provider>" provider form input
    When the provider input is accepted
    Then exactly the "<provider>" provider is selected

    Examples:
      | provider   |
      | aws        |
      | azure      |
      | gcp        |
      | kubernetes |

  Scenario Outline: Protect credential secrets
    Given a complete "<provider>" provider form input
    When the provider input is accepted
    Then its credential secrets are protected from ordinary output

    Examples:
      | provider   |
      | aws        |
      | azure      |
      | gcp        |
      | kubernetes |

  Scenario: Accept an optional AWS session token safely
    Given a complete AWS provider form input with a session token
    When the provider input is accepted
    Then the session token is protected from ordinary output

  Scenario: Reject a missing provider
    Given a form input without a provider
    When the provider input is submitted
    Then the provider input is rejected

  Scenario: Reject an unknown provider
    Given a form input with an unknown provider
    When the provider input is submitted
    Then the provider input is rejected without exposing submitted credentials

  Scenario: Reject fields outside the selected provider
    Given an AWS form input containing an Azure credential field
    When the provider input is submitted
    Then the provider input is rejected without exposing the rejected credential

  Scenario: Startup configuration remains provider-free
    Given the six standard injector startup settings
    When startup configuration is loaded
    Then no provider input is present in startup configuration

  # ---- Constraints identified ----

  Scenario Outline: Provider selection is a strict discriminator
    Given a form input with provider value "<provider>"
    When the provider input is submitted
    Then the provider input is rejected

    Examples:
      | provider |
      | AWS      |
      |  aws     |

  Scenario Outline: Required provider values cannot be blank
    Given a "<provider>" form input whose required value "<field>" is blank
    When the provider input is submitted
    Then the provider input is rejected without exposing the submitted value

    Examples:
      | provider   | field                       |
      | aws        | aws_secret_access_key       |
      | azure      | azure_client_secret         |
      | gcp        | gcp_service_account_json    |
      | kubernetes | kubernetes_kubeconfig       |
