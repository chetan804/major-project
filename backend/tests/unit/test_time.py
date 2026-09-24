"""
Time handling (BR-18 and REQ-PLT-013).

The rules being protected: storage is UTC, a naive datetime is rejected rather
than silently assumed to be UTC, and a tenant-local day is converted correctly —
which matters because collection "today" is a local-calendar concept, and
filtering on a UTC date would silently drop or include work at the boundary.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta, timezone

import pytest

from app.core.time import (
    daterange_days,
    day_bounds_utc,
    is_aware,
    isoformat_utc,
    parse_iso,
    tenant_day_bounds_utc,
    tenant_timezone,
    tenant_today,
    to_tenant_time,
    to_utc,
    utc_now,
)

pytestmark = pytest.mark.unit


def test_utc_now_is_timezone_aware() -> None:
    """A naive "now" is the root of every UTC/local bug; it must never be produced."""
    now = utc_now()

    assert is_aware(now)
    assert now.tzinfo is UTC


def test_naive_datetime_is_rejected() -> None:
    """
    A naive datetime must raise rather than be assumed to be UTC.

    Accepting it would silently reinterpret a local timestamp as UTC, shifting
    every derived figure by the local offset.
    """
    with pytest.raises(ValueError, match="Naive datetimes are not accepted"):
        to_utc(datetime(2026, 9, 24, 10, 30))  # noqa: DTZ001 - the point of the test


def test_aware_datetime_is_converted_to_utc() -> None:
    kolkata = timezone(timedelta(hours=5, minutes=30))
    converted = to_utc(datetime(2026, 9, 24, 10, 30, tzinfo=kolkata))

    assert converted.tzinfo is UTC
    assert converted.hour == 5
    assert converted.minute == 0


def test_isoformat_uses_zulu_suffix() -> None:
    """JavaScript clients expect the ``Z`` form; ``+00:00`` is inconsistently parsed."""
    rendered = isoformat_utc(datetime(2026, 9, 24, 10, 30, tzinfo=UTC))

    assert rendered == "2026-09-24T10:30:00Z"


@pytest.mark.parametrize(
    "value",
    [
        "2026-09-24T10:30:00Z",
        "2026-09-24T10:30:00z",
        "2026-09-24T10:30:00+00:00",
        "2026-09-24T16:00:00+05:30",
    ],
)
def test_parse_iso_normalises_to_utc(value: str) -> None:
    parsed = parse_iso(value)

    assert parsed.tzinfo is UTC
    assert parsed.hour == 10
    assert parsed.minute == 30


def test_parse_iso_treats_missing_offset_as_utc() -> None:
    """
    An offsetless string is read as UTC.

    This only applies to *inbound* text, which the API documents as UTC. Outbound
    datetimes are always emitted with an offset, so the ambiguity never arises in
    the other direction.
    """
    assert parse_iso("2026-09-24T10:30:00") == datetime(2026, 9, 24, 10, 30, tzinfo=UTC)


def test_tenant_day_bounds_account_for_a_half_hour_offset() -> None:
    """
    Asia/Kolkata is UTC+05:30, so its day starts at 18:30 UTC the previous day.

    An implementation that assumed whole-hour offsets would be wrong for a tenant
    in India — the primary target market for this platform — by 30 minutes, which
    is enough to mis-assign a collection to the wrong day.
    """
    start, end = tenant_day_bounds_utc(date(2026, 9, 25), "Asia/Kolkata")

    assert start == datetime(2026, 9, 24, 18, 30, tzinfo=UTC)
    assert end == datetime(2026, 9, 25, 18, 30, tzinfo=UTC)
    assert end - start == timedelta(days=1)


def test_tenant_day_bounds_are_half_open() -> None:
    """``[start, end)`` avoids double-counting the instant that closes a day."""
    start, end = tenant_day_bounds_utc(date(2026, 9, 25), "UTC")

    assert start == datetime(2026, 9, 25, 0, 0, tzinfo=UTC)
    assert end == datetime(2026, 9, 26, 0, 0, tzinfo=UTC)


def test_utc_day_bounds_are_midnight_to_midnight() -> None:
    start, end = day_bounds_utc(date(2026, 1, 1))

    assert start == datetime(2026, 1, 1, tzinfo=UTC)
    assert end == datetime(2026, 1, 2, tzinfo=UTC)


def test_tenant_today_differs_from_utc_date_across_the_boundary() -> None:
    """
    A tenant's "today" can differ from the UTC date.

    At 2026-09-24T20:00Z it is already 2026-09-25 in Kolkata (01:30 local). A
    dashboard that used the UTC date would show the previous day's collections.
    """
    instant = datetime(2026, 9, 24, 20, 0, tzinfo=UTC)

    assert tenant_today("Asia/Kolkata", now=instant) == date(2026, 9, 25)
    assert tenant_today("UTC", now=instant) == date(2026, 9, 24)


def test_to_tenant_time_converts_for_presentation() -> None:
    instant = datetime(2026, 9, 24, 20, 0, tzinfo=UTC)
    local = to_tenant_time(instant, "Asia/Kolkata")

    assert local.hour == 1 and local.minute == 30
    assert local.day == 25


def test_unknown_timezone_raises_rather_than_defaulting() -> None:
    """
    An unknown zone must raise.

    Silently falling back to UTC would misdate every collection and report for
    that tenant — a wrong answer is worse than a refused one.
    """
    with pytest.raises(ValueError, match="Unknown timezone"):
        tenant_timezone("Mars/Olympus_Mons")

    with pytest.raises(ValueError, match="Unknown timezone"):
        tenant_day_bounds_utc(date(2026, 1, 1), "Not/AZone")


def test_daterange_days_is_inclusive() -> None:
    """An inclusive range of a single day is one day, not zero."""
    assert daterange_days(date(2026, 1, 1), date(2026, 1, 1)) == 1
    assert daterange_days(date(2026, 1, 1), date(2026, 1, 31)) == 31


def test_is_aware_handles_non_utc_offsets() -> None:
    assert is_aware(datetime(2026, 1, 1, tzinfo=timezone(timedelta(hours=-5))))
