class ShodanClientError(Exception):
    """Base class for all Shodan client exceptions."""

    pass


class MissingRequiredFieldError(ShodanClientError):
    """Raised when a required field is missing in the input data."""

    pass


class InvalidContractError(ShodanClientError):
    """Raised when a provided contract ID or name is invalid."""

    pass


class InvalidTargetPropertySelectorError(ShodanClientError):
    """Raised when the target property selector is unsupported or invalid."""

    pass


class InvalidTargetFieldError(ShodanClientError):
    """Raised when a target field is unsupported or invalid."""

    pass


class NoTargetsRecovered(ShodanClientError):
    """Raised when no targets could be resolved from input data."""

    pass
