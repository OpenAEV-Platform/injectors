class EmailSMTPInjectorError(Exception):
    """Base class for all email SMTP injector exceptions."""

    pass


class InvalidContractError(EmailSMTPInjectorError, ValueError):
    """Raised when a provided contract ID is invalid or unsupported."""

    pass


class MissingRequiredFieldError(EmailSMTPInjectorError, ValueError):
    """Raised when a required field is missing in the input data."""

    pass


class AttachmentDownloadError(EmailSMTPInjectorError):
    """Raised when an inject attachment cannot be downloaded."""

    pass


class CustomHeaderValidationError(EmailSMTPInjectorError, ValueError):
    """Raised when a custom email header is malformed or unsafe."""

    pass
