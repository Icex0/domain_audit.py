"""Custom exceptions for domain_audit."""


class DomainAuditError(Exception):
    """Base exception for domain audit errors."""
    pass


class AuthenticationError(DomainAuditError):
    """Raised when authentication fails."""
    pass


class ConnectionError(DomainAuditError):
    """Raised when connection to AD fails."""
    pass


class EnumerationError(DomainAuditError):
    """Raised when enumeration fails."""
    pass


class CheckError(DomainAuditError):
    """Raised when a security check fails."""
    pass


class ToolNotFoundError(DomainAuditError):
    """Raised when a required external tool is not found."""
    pass


class OutputError(DomainAuditError):
    """Raised when output operations fail."""
    pass
