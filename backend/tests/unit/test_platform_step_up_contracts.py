"""Confirmation expiry boundaries and password schema privacy."""

import secrets
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from app.api.schemas.platform_step_up import PlatformStepUpRequest
from app.models.identity import Session
from app.services.platform_access import STEP_UP_LIFETIME, step_up_expiry

pytestmark = pytest.mark.unit
NOW = datetime(2026, 9, 29, 12, tzinfo=UTC)


@pytest.mark.parametrize(
    "age,valid", [(0, True), (299, True), (300, False), (301, False), (-1, False)]
)
def test_expiry_is_half_open_and_future_verification_fails(age, valid):
    live = Session(
        issued_at=NOW - timedelta(hours=1),
        expires_at=NOW + timedelta(hours=1),
        platform_reauthenticated_at=NOW - timedelta(seconds=age),
    )
    assert (step_up_expiry(live, NOW) is not None) is valid
    if valid:
        assert step_up_expiry(live, NOW) == live.platform_reauthenticated_at + STEP_UP_LIFETIME


@pytest.mark.parametrize("state", ["missing", "pre_session", "revoked", "expired"])
def test_session_state_always_bounds_confirmation(state):
    live = Session(
        issued_at=NOW - timedelta(seconds=10),
        expires_at=NOW + timedelta(hours=1),
        platform_reauthenticated_at=NOW,
    )
    if state == "missing":
        live.platform_reauthenticated_at = None
    elif state == "pre_session":
        live.platform_reauthenticated_at = live.issued_at - timedelta(seconds=1)
    elif state == "revoked":
        live.revoked_at = NOW
    else:
        live.expires_at = NOW
    assert step_up_expiry(live, NOW) is None


def test_session_expiry_caps_the_five_minute_window():
    live = Session(
        issued_at=NOW, expires_at=NOW + timedelta(seconds=40), platform_reauthenticated_at=NOW
    )
    assert step_up_expiry(live, NOW) == live.expires_at


def test_password_input_preserves_whitespace_but_hides_repr():
    password = "  " + secrets.token_urlsafe(24) + "  "
    payload = PlatformStepUpRequest(password=password)
    assert payload.password == password
    assert password not in repr(payload)
    with pytest.raises(ValidationError):
        PlatformStepUpRequest(password=password, session_id="untrusted")
