"""Opaque credential and closed delegation contract; no hard-coded usable keys."""

from __future__ import annotations

import json
import secrets
from datetime import timedelta

import pytest

from app.authorization.api_keys import API_KEY_SCOPES, api_key_prefix, generate_api_key
from app.authorization.permissions import PERMISSION_CODES
from app.core.audit_privacy import safe_audit_data
from app.core.errors import InputValidationError
from app.core.time import utc_now
from app.services.api_keys import ApiKeyService, IssuedApiKey

pytestmark = pytest.mark.unit


def test_key_format_uniqueness_and_repr_safety():
    generated = [generate_api_key() for _ in range(100)]
    assert len({prefix for prefix, _ in generated}) == 100
    for prefix, plaintext in generated:
        assert len(prefix) == 12 and len(plaintext) == 56
        assert api_key_prefix(plaintext) == prefix
        assert api_key_prefix(plaintext + " ") is None
        assert plaintext not in repr(IssuedApiKey(None, plaintext))


def test_scope_delegation_is_explicit_and_excludes_human_and_platform_grants():
    assert {"bins.telemetry.ingest"} == API_KEY_SCOPES
    assert API_KEY_SCOPES.issubset(PERMISSION_CODES)
    for scope in set(PERMISSION_CODES) - API_KEY_SCOPES:
        with pytest.raises(InputValidationError):
            ApiKeyService._scopes([scope])


def test_service_expiry_checks_cannot_be_bypassed_by_non_http_callers():
    for value in (
        utc_now() - timedelta(seconds=1),
        utc_now().replace(tzinfo=None),
        utc_now() + timedelta(days=366),
    ):
        with pytest.raises(InputValidationError):
            ApiKeyService._expiry(value)
    assert timedelta(days=89) < ApiKeyService._expiry(None) - utc_now() <= timedelta(days=90)


def test_api_key_material_and_hash_fields_are_redacted():
    secret = secrets.token_urlsafe(32)
    plaintext = generate_api_key()[1]
    result = safe_audit_data(
        {
            "api_key": secret,
            "key_hash": secret,
            "nested": {"keyHash": secret},
            "description": "credential " + plaintext,
        }
    )
    assert plaintext not in json.dumps(result)
    assert secret not in json.dumps(result)
