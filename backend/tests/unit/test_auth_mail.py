"""Mail transport contract. SMTP network delivery is not asserted by these tests."""

from __future__ import annotations

import secrets
import ssl
from uuid import uuid4

import pytest
from cryptography.fernet import Fernet

from app.core.config import Settings
from app.core.logging import REDACTED, redact_event
from app.integrations.auth_mail import Mail, SMTPTransport, mime_message, transport_for

pytestmark = pytest.mark.unit


def settings(**values):
    return Settings(_env_file=None, jwt_secret_key=secrets.token_urlsafe(48), **values)


@pytest.mark.parametrize("tls_fails", [False, True])
async def test_smtp_requires_tls_before_authentication_and_submission(monkeypatch, tls_fails):
    events = []

    class Client:
        def __init__(self, host, port, timeout):
            assert (host, port, timeout) == ("smtp.example.test", 587, 10)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def ehlo(self):
            events.append("ehlo")

        def starttls(self, context):
            assert context.verify_mode == ssl.CERT_REQUIRED
            assert context.check_hostname
            events.append("tls")
            if tls_fails:
                raise ssl.SSLError("TLS unavailable")

        def login(self, user, password):
            events.append("login")

        def send_message(self, message):
            events.append("send")
            assert message["Message-ID"].startswith("<")
            return {}

    monkeypatch.setattr("app.integrations.auth_mail.smtplib.SMTP", Client)
    provider = SMTPTransport(
        settings(
            smtp_host="smtp.example.test",
            smtp_username="user",
            smtp_password=secrets.token_urlsafe(24),
        )
    )
    mail = Mail(uuid4(), uuid4(), "user@example.test", "Verification", "private body")
    assert "private body" not in repr(mail)
    if tls_fails:
        with pytest.raises(ssl.SSLError):
            await provider.send(mail)
        assert events == ["ehlo", "tls"]
    else:
        await provider.send(mail)
        assert events == ["ehlo", "tls", "ehlo", "login", "send"]


@pytest.mark.parametrize("environment", ["staging", "production"])
def test_local_mailbox_is_forbidden_outside_development(environment):
    with pytest.raises(RuntimeError, match="forbidden"):
        transport_for(settings(environment=environment, email_provider="console"))


def test_delivery_key_and_production_rate_configuration_are_validated():
    invalid = settings(auth_delivery_enabled=True, auth_mail_encryption_key="")
    assert any("AUTH_MAIL_ENCRYPTION_KEY" in p for p in invalid.validate_for_startup())
    valid = settings(
        auth_delivery_enabled=True, auth_mail_encryption_key=Fernet.generate_key().decode()
    )
    assert valid.validate_for_startup() == []
    shared = valid.model_copy(update={"jwt_secret_key": valid.auth_mail_encryption_key})
    assert any("distinct" in problem for problem in shared.validate_for_startup())
    for changes in ({"rate_limit_enabled": False}, {"redis_adapter": "fakeredis"}):
        bad = settings(environment="production", **changes)
        assert any("rate limits" in p for p in bad.validate_for_startup())


def test_mail_key_is_redacted_from_structured_logs():
    value = Fernet.generate_key().decode()
    result = redact_event(
        None, "info", {"auth_mail_encryption_key": value, "encrypted_payload": value}
    )
    assert result["auth_mail_encryption_key"] == REDACTED
    assert result["encrypted_payload"] == REDACTED


@pytest.mark.parametrize(
    "recipient",
    ["a@example.test, b@example.test", "local-only", "a@example.test\nBcc: b@example.test"],
)
def test_mail_never_accepts_multiple_or_injected_recipients(recipient):
    with pytest.raises(ValueError):
        mime_message(
            Mail(uuid4(), uuid4(), recipient, "Verification", "private body"), "sender@example.test"
        )
