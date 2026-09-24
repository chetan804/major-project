"""
Time handling.

BR-18 requires that timestamps are stored in UTC and converted to a tenant's
timezone only at the presentation layer, and forbids silently mixing local and
UTC values. This module is the only sanctioned way to obtain "now", so a
naive datetime cannot accidentally enter the system.

``ruff``'s ``DTZ`` rules are enabled precisely so that a bare
``datetime.now()`` or ``datetime.utcnow()`` anywhere in the application is a
lint failure rather than a subtle bug.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, time, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

__all__ = [
    "daterange_days",
    "day_bounds_utc",
    "is_aware",
    "isoformat_utc",
    "parse_iso",
    "tenant_day_bounds_utc",
    "tenant_timezone",
    "tenant_today",
    "to_tenant_time",
    "to_utc",
    "utc_now",
]


def utc_now() -> datetime:
    """Current time as a timezone-aware UTC datetime."""
    return datetime.now(tz=UTC)


def to_utc(value: datetime) -> datetime:
    """
    Convert a datetime to UTC.

    A naive datetime is rejected rather than assumed to be UTC: guessing is how
    local and UTC values get mixed, which BR-18 forbids.
    """
    if value.tzinfo is None:
        raise ValueError(
            "Naive datetimes are not accepted. Construct with an explicit "
            "timezone (see app.core.time.utc_now) so local and UTC values can "
            "never be confused (BR-18)."
        )
    return value.astimezone(UTC)


def is_aware(value: datetime) -> bool:
    """Whether the datetime carries timezone information."""
    return value.tzinfo is not None and value.tzinfo.utcoffset(value) is not None


def isoformat_utc(value: datetime) -> str:
    """Render a datetime as ISO-8601 with a ``Z`` suffix, in UTC."""
    return to_utc(value).isoformat().replace("+00:00", "Z")


def parse_iso(value: str) -> datetime:
    """
    Parse an ISO-8601 string, defaulting to UTC when no offset is given.

    Accepts the ``Z`` suffix that JavaScript clients emit, which
    ``datetime.fromisoformat`` handles natively from Python 3.11 onwards.
    """
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if not is_aware(parsed):
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def tenant_timezone(name: str) -> ZoneInfo:
    """
    Resolve a tenant timezone name.

    Falls back to UTC with an explicit error only for an unknown name; returning
    a silent wrong-zone value would misdate collections and reports.
    """
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError, KeyError) as exc:
        raise ValueError(f"Unknown timezone: {name!r}") from exc


def to_tenant_time(value: datetime, timezone_name: str) -> datetime:
    """Convert a stored UTC datetime into the tenant's local time for display."""
    return to_utc(value).astimezone(tenant_timezone(timezone_name))


def tenant_today(timezone_name: str, *, now: datetime | None = None) -> date:
    """The current calendar date in the tenant's timezone."""
    local = to_tenant_time(now or utc_now(), timezone_name)
    return local.date()


def tenant_day_bounds_utc(day: date, timezone_name: str) -> tuple[datetime, datetime]:
    """
    Half-open UTC bounds ``[start, end)`` for a calendar day in a tenant's zone.

    This is the correct way to select "today's collections" for a tenant: a
    tenant-local day does not align with a UTC day, so filtering on a UTC date
    would silently drop or include work at the boundary.
    """
    zone = tenant_timezone(timezone_name)
    start_local = datetime.combine(day, time.min, tzinfo=zone)
    end_local = start_local + timedelta(days=1)
    return start_local.astimezone(UTC), end_local.astimezone(UTC)


def day_bounds_utc(day: date) -> tuple[datetime, datetime]:
    """Half-open UTC bounds ``[start, end)`` for a UTC calendar day."""
    start = datetime.combine(day, time.min, tzinfo=UTC)
    return start, start + timedelta(days=1)


def daterange_days(start: date, end: date) -> int:
    """Number of days in the inclusive range, used to bound report windows."""
    return (end - start).days + 1
