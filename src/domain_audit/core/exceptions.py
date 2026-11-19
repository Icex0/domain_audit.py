"""Custom exceptions for domain_audit."""


class DomainAuditError(Exception):
    """Base exception for domain audit errors."""




class ConnectionError(DomainAuditError):
    """Raised when connection to AD fails."""


class EnumerationError(DomainAuditError):
    """Raised when enumeration fails."""

