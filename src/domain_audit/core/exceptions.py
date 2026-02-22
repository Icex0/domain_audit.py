"""Custom exceptions for domain_audit."""


class DomainAuditError(Exception):
    """Base exception for domain audit errors."""
    pass




class ConnectionError(DomainAuditError):
    """Raised when connection to AD fails."""
    pass


class EnumerationError(DomainAuditError):
    """Raised when enumeration fails."""
    pass

