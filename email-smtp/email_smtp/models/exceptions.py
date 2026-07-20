class EmailInjectorError(Exception):
    """Base class for all email injector exceptions."""

    pass


class InvalidContractError(EmailInjectorError, ValueError):
    """Raised when a provided contract ID is invalid or unsupported."""

    pass


class MissingRequiredFieldError(EmailInjectorError, ValueError):
    """Raised when a required field is missing in the input data."""

    pass


class AttachmentDownloadError(EmailInjectorError):
    """Raised when an inject attachment cannot be downloaded."""

    pass
