"""Custom exceptions for AWS documentation parsing errors."""


class AWSDocParsingError(Exception):
    """Base exception for AWS documentation parsing errors."""
    pass


class AWSDocStructureError(AWSDocParsingError):
    """Raised when AWS documentation structure has changed unexpectedly."""
    pass


class TableNotFoundError(AWSDocParsingError):
    """Raised when an expected table is not found in the documentation."""
    pass


class MissingExpectedSectionError(AWSDocParsingError):
    """Raised when an expected section is missing from the documentation."""
    pass
