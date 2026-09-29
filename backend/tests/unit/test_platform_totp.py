"""Published RFC 6238 vectors, encryption binding, proof policy and secret handling."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from app.api.schemas.platform_mfa import MfaEnrollmentResponse, MfaRecoveryResponse
from app.authorization.totp import generate_code, match_counter, new_seed
from app.core.audit_privacy import safe_audit_data
from app.core.errors import DependencyUnavailableError, PermissionDeniedError
from app.models.identity import Session, User
from app.services.platform_access import require_recent_step_up
from app.services.platform_mfa import decrypt_seed, encrypt_seed, recovery_codes

pytestmark = pytest.mark.unit
# Public RFC 6238 Appendix B test material, not an application credential.
RFC_INPUT = b"12345678901234567890"
RFC_BASE32 = base64.b32encode(RFC_INPUT).decode()


@pytest.mark.parametrize(
    "when,expected",
    [
        (59, "287082"),
        (1111111109, "081804"),
        (1111111111, "050471"),
        (1234567890, "005924"),
        (2000000000, "279037"),
        (20000000000, "353130"),
    ],
)
def test_rfc6238_sha1_vectors_truncated_to_six_digits(when, expected):
    assert generate_code(RFC_BASE32, when // 30) == expected


@pytest.mark.parametrize(
    "offset,valid", [(-2, False), (-1, True), (0, True), (1, True), (2, False)]
)
def test_only_one_step_skew_is_accepted(offset, valid):
    now = datetime.fromtimestamp(1234567890, UTC)
    current = int(now.timestamp()) // 30
    value = generate_code(RFC_BASE32, current + offset)
    assert (match_counter(RFC_BASE32, value, now) is not None) is valid
    assert match_counter(RFC_BASE32, value, now, current + 1) is None


@pytest.mark.parametrize(
    "value", ["", "12345", "1234567", "\uff11\uff12\uff13\uff14\uff15\uff16", "12345x", "123456\n"]
)
def test_non_ascii_or_malformed_otp_is_refused(value):
    assert match_counter(RFC_BASE32, value, datetime.now(UTC)) is None


def test_generated_seeds_and_recovery_values_are_distinct():
    seeds = {new_seed() for _ in range(50)}
    assert len(seeds) == 50
    assert all(len(base64.b32decode(seed)) == 20 for seed in seeds)
    user = User()
    codes = recovery_codes(user)
    assert len(set(codes)) == 10
    assert all(len(code) == 36 and code not in user.mfa_recovery_hashes for code in codes)


def test_ciphertext_is_bound_to_principal_and_factor(test_settings):
    user = User(id=uuid4(), tenant_id=uuid4())
    factor = uuid4()
    seed = new_seed()
    ciphertext = encrypt_seed(test_settings, user, seed, factor)
    assert seed not in ciphertext
    assert decrypt_seed(test_settings, user, ciphertext) == (seed, factor)
    for other in (User(id=uuid4(), tenant_id=user.tenant_id), User(id=user.id, tenant_id=uuid4())):
        with pytest.raises(DependencyUnavailableError):
            decrypt_seed(test_settings, other, ciphertext)


@pytest.mark.parametrize("source", ["missing", "mail", "invalid"])
def test_encryption_configuration_cannot_share_other_keys(test_settings, source):
    test_settings.mfa_encryption_key = {
        "missing": "",
        "mail": test_settings.auth_mail_encryption_key,
        "invalid": "invalid",
    }[source]
    with pytest.raises(DependencyUnavailableError):
        encrypt_seed(test_settings, User(id=uuid4(), tenant_id=uuid4()), new_seed(), uuid4())


@pytest.mark.parametrize(
    "state", ["password_only", "wrong_factor", "wrong_time", "partial_counter"]
)
def test_enrolled_proof_requires_matching_factor_and_same_confirmation_time(monkeypatch, state):
    now = datetime.now(UTC)
    monkeypatch.setattr("app.services.platform_access.utc_now", lambda: now)
    factor_id = uuid4()
    user = User(mfa_factor_id=factor_id)
    session = Session(
        issued_at=now - timedelta(minutes=1),
        expires_at=now + timedelta(hours=1),
        platform_reauthenticated_at=now,
        platform_mfa_factor_id=factor_id,
        platform_mfa_verified_at=now,
    )
    require_recent_step_up(session, user)
    if state == "password_only":
        session.platform_mfa_verified_at = None
    elif state == "wrong_factor":
        session.platform_mfa_factor_id = uuid4()
    elif state == "wrong_time":
        session.platform_mfa_verified_at = now - timedelta(seconds=1)
    else:
        user.mfa_factor_id = None
        user.mfa_last_counter = 1
        session.platform_mfa_verified_at = None
    with pytest.raises(PermissionDeniedError):
        require_recent_step_up(session, user)


def test_provisioning_and_backup_material_are_redacted():
    seed = new_seed()
    codes = recovery_codes(User())
    uri = "otpauth://totp/EcoMind?secret=" + seed
    issued = MfaEnrollmentResponse(secret=seed, otpauth_uri=uri, expires_at=datetime.now(UTC))
    backup = MfaRecoveryResponse(recovery_codes=codes)
    assert seed not in repr(issued) and codes[0] not in repr(backup)
    sanitized = safe_audit_data(
        {
            "secret": seed,
            "totp_code": "123456",
            "recovery_codes": codes,
            "otpauth_uri": uri,
            "description": uri,
            "notes": codes[0],
        }
    )
    text = json.dumps(sanitized)
    assert all(value not in text for value in [seed, "123456", *codes])


@pytest.mark.parametrize(
    "field,value", [("seed", "0" * 32), ("factor", 1), ("factor", None), ("purpose", "unknown")]
)
def test_malformed_encrypted_payload_fails_closed(test_settings, field, value):
    from app.services.platform_mfa import cipher

    user = User(id=uuid4(), tenant_id=uuid4())
    data = {
        "purpose": "platform_totp_v1",
        "tenant": str(user.tenant_id),
        "user": str(user.id),
        "factor": str(uuid4()),
        "seed": new_seed(),
    }
    data[field] = value
    payload = cipher(test_settings).encrypt(json.dumps(data).encode()).decode()
    with pytest.raises(DependencyUnavailableError):
        decrypt_seed(test_settings, user, payload)


@pytest.mark.parametrize("kind", ["invalid", "mail", "independent", "empty"])
def test_startup_validates_optional_independent_mfa_key(test_settings, kind):
    from cryptography.fernet import Fernet

    test_settings.mfa_encryption_key = {
        "invalid": "invalid",
        "mail": test_settings.auth_mail_encryption_key,
        "independent": Fernet.generate_key().decode(),
        "empty": "",
    }[kind]
    issues = [
        issue for issue in test_settings.validate_for_startup() if "MFA_ENCRYPTION_KEY" in issue
    ]
    assert bool(issues) is (kind in {"invalid", "mail"})


@pytest.mark.parametrize("other_field", ["auth_mail_encryption_key", "jwt_secret_key"])
@pytest.mark.parametrize("alias_location", ["mfa", "other"])
def test_equivalent_base64_key_is_not_independent(test_settings, alias_location, other_field):
    from cryptography.fernet import Fernet

    from app.services.platform_mfa import cipher

    original = Fernet.generate_key().decode()
    setattr(test_settings, other_field, original)
    test_settings.mfa_encryption_key = original
    if alias_location == "mfa":
        test_settings.mfa_encryption_key = original + "\n"
    else:
        setattr(test_settings, other_field, original + "\n")
    assert any("distinct" in issue for issue in test_settings.validate_for_startup())
    with pytest.raises(DependencyUnavailableError):
        cipher(test_settings)
