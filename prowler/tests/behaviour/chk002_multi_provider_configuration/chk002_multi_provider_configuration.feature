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

  Scenario Outline: Keep accepted provider input immutable
    Given a complete "<provider>" provider form input
    When the provider input is accepted
    Then neither ordinary fields nor credential secrets can be replaced

    Examples:
      | provider   |
      | aws        |
      | azure      |
      | gcp        |
      | kubernetes |

  Scenario Outline: Safely snapshot accepted provider input
    Given a complete "<provider>" provider form input
    When the provider input is deeply copied
    Then the snapshot preserves protected credential values without exposing them

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

  Scenario: Accept a kubeconfig with inline credentials only
    Given a Kubernetes form input whose kubeconfig carries an inline token and CA data
    When the provider input is parsed at the provider boundary
    Then the provider input is accepted

  Scenario Outline: Reject kubeconfig settings that can run commands or read host files
    Given a Kubernetes form input whose kubeconfig contains <setting>
    When the provider input is parsed at the provider boundary
    Then the provider input is rejected at the kubeconfig without echoing it

    Examples:
      | setting                              |
      | an exec credential plugin            |
      | an auth-provider command             |
      | a token file path                    |
      | a client certificate file path       |
      | a certificate authority file path    |
      | an unknown top-level setting         |
      | a YAML alias                         |
      | a document that is not a mapping     |
      | invalid YAML                         |

  Scenario Outline: Accept only Prowler-supported Azure cloud environments
    Given an Azure form input whose cloud environment is <environment>
    When the provider input is parsed at the provider boundary
    Then the provider input is <outcome>

    Examples:
      | environment       | outcome  |
      | AzureCloud        | accepted |
      | AzureChinaCloud   | accepted |
      | AzureUSGovernment | accepted |
      | Microsoft.Compute | rejected |
      | azurecloud        | rejected |

  Scenario Outline: Reject NUL characters in provider input
    Given an AWS form input whose <field> contains a NUL character
    When the provider input is parsed at the provider boundary
    Then the provider input is rejected at that field without echoing it

    Examples:
      | field                 |
      | aws_region            |
      | aws_secret_access_key |
      | aws_endpoint_url      |

  Scenario Outline: Parse provider input without retaining submitted values
    Given a <rejected> provider form input carrying a credential
    When the provider input is parsed at the provider boundary
    Then only value-free issue locations and categories are reported
    And the rejection keeps no reference to the submitted payload

    Examples:
      | rejected                |
      | unknown provider        |
      | cross-provider field    |
      | credential-bearing endpoint |
      | non-string credential   |

  Scenario: Startup configuration remains provider-free
    Given the six standard injector startup settings
    When startup configuration is loaded
    Then no provider input is present in startup configuration

  Scenario: Keep AWS endpoint overrides out of startup configuration
    Given an AWS endpoint override appears in environment or YAML startup input
    When startup configuration is loaded
    Then the AWS endpoint override is not exposed by startup configuration

  Scenario: Use the recommended Prowler executable by default
    Given no Prowler executable path is configured
    When startup configuration is loaded
    Then the Prowler executable path is "/usr/local/bin/prowler"

  Scenario: Configure an absolute Prowler executable path
    Given an absolute Prowler executable path is configured
    When startup configuration is loaded
    Then that Prowler executable path is available as ordinary runtime configuration

  Scenario Outline: Reject an invalid Prowler executable path
    Given the Prowler executable path is "<path>"
    When startup configuration is loaded
    Then the startup configuration is rejected

    Examples:
      | path             |
      |                  |
      |                  |
      | bin/prowler      |

  Scenario: Use the default AWS service endpoint for an assessment
    Given an AWS provider input without an endpoint override
    When the provider input is accepted
    Then the AWS endpoint override is absent

  Scenario: Supply a trusted AWS endpoint override per assessment
    Given an AWS provider input with an absolute HTTP or HTTPS endpoint URL
    When the provider input is accepted
    Then that endpoint is available as an ordinary string without a reachability check

  Scenario Outline: Reject an unsafe AWS endpoint override
    Given an AWS provider input whose endpoint override is "<endpoint>"
    When the provider input is submitted
    Then the provider input is rejected

    Examples:
      | endpoint                              |
      |                                       |
      | /relative                             |
      | https:///missing-host                 |
      | ftp://localhost:4566                  |
      | https://user:password@aws.example.com |
      | https://aws.example.com?region=local  |
      | https://aws.example.com#credentials   |

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

  Scenario: Reject a non-string AWS endpoint override
    Given an AWS provider input whose endpoint override is a non-string value
    When the provider input is submitted
    Then the provider input is rejected before type coercion

  Scenario: Reject an AWS endpoint override with an empty explicit port
    Given an AWS provider input whose endpoint override has a port delimiter without a port
    When the provider input is submitted
    Then the provider input is rejected
