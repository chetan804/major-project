"""Recovery delivery transports. Local mail is a private file, never a log line.

SMTP success means the relay accepted the message, not that it reached an inbox.
The worker owns retries. Transports must not log recipient, content or credentials.
"""

from __future__ import annotations

import asyncio
import os
import smtplib
import ssl
import tempfile
from dataclasses import dataclass
from email.headerregistry import Address
from email.message import EmailMessage
from email.policy import SMTP
from pathlib import Path
from typing import Protocol
from uuid import UUID

from app.core.config import Settings


@dataclass(frozen=True, repr=False)
class Mail:
    id: UUID
    tenant_id: UUID
    recipient: str
    subject: str
    body: str


class MailTransport(Protocol):
    async def send(self, mail: Mail) -> None: ...


def mime_message(mail: Mail, sender: str) -> EmailMessage:
    message = EmailMessage(policy=SMTP)
    message["From"] = Address(addr_spec=sender)
    recipient = Address(addr_spec=mail.recipient)
    if not recipient.username or not recipient.domain:
        raise ValueError("A single recipient mailbox address is required")
    message["To"] = recipient
    message["Subject"] = mail.subject
    message["Message-ID"] = f"<{mail.id}@ecomind.local>"
    message.set_content(mail.body)
    return message


class LocalMailbox:
    def __init__(self, root: Path, sender: str) -> None:
        self.root = root
        self.sender = sender

    async def send(self, mail: Mail) -> None:
        await asyncio.to_thread(self._write, mail)

    def _write(self, mail: Mail) -> None:
        # UUID-only path components; user-controlled addresses never become paths.
        directory = self.root / str(mail.tenant_id)
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        directory.chmod(0o700)
        destination = directory / f"{mail.id}.eml"
        # A retry replaces the same message atomically instead of duplicating it.
        fd, temporary_name = tempfile.mkstemp(prefix=f".{mail.id}.", suffix=".tmp", dir=directory)
        temporary = Path(temporary_name)
        try:
            with os.fdopen(fd, "wb") as output:
                output.write(mime_message(mail, self.sender).as_bytes())
                output.flush()
                os.fsync(output.fileno())
            temporary.replace(destination)
        finally:
            temporary.unlink(missing_ok=True)


class SMTPTransport:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def send(self, mail: Mail) -> None:
        await asyncio.to_thread(self._send, mail)

    def _send(self, mail: Mail) -> None:
        s = self.settings
        message = mime_message(mail, s.smtp_from_address)
        # Fail rather than downgrade if STARTTLS or certificate validation fails.
        with smtplib.SMTP(s.smtp_host, s.smtp_port, timeout=s.smtp_timeout_seconds) as smtp:
            smtp.ehlo()
            smtp.starttls(context=ssl.create_default_context())
            smtp.ehlo()
            if s.smtp_username:
                smtp.login(s.smtp_username, s.smtp_password)
            refused = smtp.send_message(message)
            if refused:
                raise RuntimeError("SMTP recipient refused")


def transport_for(settings: Settings) -> MailTransport:
    if settings.email_provider == "smtp":
        return SMTPTransport(settings)
    if settings.environment not in ("development", "test"):
        raise RuntimeError("Local mailbox is forbidden outside development/test")
    root = Path(settings.auth_mailbox_root)
    if not root.is_absolute():
        root = Path(__file__).resolve().parents[3] / root
    return LocalMailbox(root, settings.smtp_from_address)
