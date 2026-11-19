"""Active Directory timestamp helpers."""

from datetime import datetime, timedelta, timezone
from typing import Optional

# Seconds between 1601-01-01 (Windows FILETIME epoch) and 1970-01-01
_FILETIME_EPOCH_OFFSET = 11644473600
_NEVER = 0x7FFFFFFFFFFFFFFF


def to_datetime(value) -> Optional[datetime]:
    """Convert an AD timestamp to an aware UTC datetime.

    Accepts what ldap3 returns (a datetime, formatted via the schema), a raw
    FILETIME (int or numeric string, 100 ns intervals since 1601) or a list
    with one of those. Returns None for "not set" values: missing, 0,
    the 1601 epoch, negative and "never" (0x7FFFFFFFFFFFFFFF).
    """
    if isinstance(value, (list, tuple)):
        value = value[0] if value else None
    if value is None or value == '':
        return None
    if isinstance(value, datetime):
        value = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        if value.year <= 1601 or value.year >= 9999:
            return None
        return value
    try:
        filetime = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    if filetime <= 0 or filetime >= _NEVER:
        return None
    return datetime.fromtimestamp(filetime / 10_000_000 - _FILETIME_EPOCH_OFFSET, tz=timezone.utc)


def older_than(value, days: int) -> Optional[bool]:
    """True if the timestamp is more than `days` ago, False if not, None if not set."""
    dt = to_datetime(value)
    if dt is None:
        return None
    return dt < datetime.now(timezone.utc) - timedelta(days=days)
