"""
Tests for the secret scanner.

A scanner that finds nothing is ambiguous: it may mean the repository is clean, or
that the patterns do not match anything at all. Those two states are identical
from the outside, and the second one is dangerous because the build stays green
while providing no protection.

These tests remove the ambiguity by proving the scanner catches each credential
shape it claims to catch, using synthetic values that are structurally valid but
belong to no one, and by proving it does *not* flag the settings that legitimately
look similar. The negative cases carry equal weight: a control that reports a
problem on a correct file gets disabled, and a disabled control protects nothing.

Every credential-shaped string below is fabricated. None is, or was, a working
credential for any service, and each is assembled from fragments at runtime rather
than written as a literal — see the sample block below for why that matters.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

pytestmark = pytest.mark.architecture

REPO_ROOT = Path(__file__).resolve().parents[3]

# ---------------------------------------------------------------------------
# Synthetic credential samples
#
# Every value below is fabricated and belongs to no service. Each is assembled
# from fragments *at runtime* rather than written as one literal, and that is
# deliberate: this repository's own secret scanner has no exemptions, and this
# file is tracked. A complete credential shape written here would be reported by
# the scanner that this file tests, and the tempting fix — carve out an exemption
# for this path — would create exactly the blind spot the scanner exists to close.
# Assembling the value keeps the control strict: there is no path, name or comment
# that an attacker could point a real credential at.
# ---------------------------------------------------------------------------
PRIVATE_KEY_HEADER = "-----BEGIN RSA " + "PRIVATE KEY-----"
AWS_ACCESS_KEY_ID = "AKIA" + "IOSFODNN7" + "EXAMPLE"
GOOGLE_API_KEY = "AIza" + "SyA1234567890abcdefghijklmnopqrstuv"
GITHUB_TOKEN = "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
SLACK_TOKEN = "xoxb-" + "123456789012-abcdefghijklmnop"
JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    + "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
    + "dQw4w9WgXcQ7Kk8mZ2vBn4pLr6tYx1aBcDeFgHiJkL"
)
CONNECTION_STRING = "postgresql://app:" + "hunter2secret" + "@db.internal:5432/app"

#: A high-entropy value assigned to a secret-named variable: the shape of the most
#: common real leak, and the one the scanner's own detection test feeds it. Assembled
#: for the same reason as the values above.
HIGH_ENTROPY_SECRET = "9f4c1a2b" + "7d8e4f6a" + "9b3c5d7e" + "8f1a2b3c" + "4d5e6f70"
HARDCODED_ASSIGNMENT = 'jwt_secret_key = "' + HIGH_ENTROPY_SECRET + '"'


def _load_scanner() -> ModuleType:
    """
    Import ``scripts/check_secrets.py`` as a module.

    ``scripts`` is not an importable package: it holds operational entry points
    rather than library code, and adding ``__init__.py`` would suggest it can be
    imported from the application, which it must not be.
    """
    path = REPO_ROOT / "scripts" / "check_secrets.py"
    spec = importlib.util.spec_from_file_location("check_secrets", path)
    assert spec is not None and spec.loader is not None, f"cannot load {path}"
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_secrets"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def scanner() -> ModuleType:
    return _load_scanner()


def _scan_line(scanner: ModuleType, line: str) -> list[str]:
    """Run the file-level scan over a single synthetic line."""
    return scanner.scan_text(REPO_ROOT / "synthetic.py", line)


# ---------------------------------------------------------------------------
# Positive cases: each rule must match its own shape
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("rule_name", "sample", "description"),
    [
        (
            "private-key-block",
            PRIVATE_KEY_HEADER,
            "an embedded private key",
        ),
        (
            "aws-access-key-id",
            f"AWS_ACCESS_KEY_ID={AWS_ACCESS_KEY_ID}",
            "an AWS access key id",
        ),
        (
            "google-api-key",
            f"API_KEY={GOOGLE_API_KEY}",
            "a Google API key",
        ),
        (
            "github-token",
            f"token = {GITHUB_TOKEN}",
            "a GitHub personal access token",
        ),
        (
            "slack-token",
            f"webhook = {SLACK_TOKEN}",
            "a Slack bot token",
        ),
        (
            "connection-string-with-password",
            f'DATABASE_URL="{CONNECTION_STRING}"',
            "a connection URL with an inline password",
        ),
    ],
)
def test_each_credential_shape_is_detected(
    scanner: ModuleType, rule_name: str, sample: str, description: str
) -> None:
    """Every rule must fire on a value of the shape it exists to catch."""
    findings = _scan_line(scanner, sample)

    assert any(rule_name in finding for finding in findings), (
        f"the scanner did not detect {description}, so it would not detect a real "
        f"one either. Findings were: {findings}"
    )


def test_a_jwt_is_detected(scanner: ModuleType) -> None:
    """
    A JWT is detected by shape.

    Separated from the parametrised cases because the fabricated token below is long
    and would obscure the rest of the table.
    """
    sample = f"SESSION_TOKEN={JWT}"

    assert any("jwt" in finding for finding in _scan_line(scanner, sample))


def test_a_hardcoded_secret_assignment_is_detected(scanner: ModuleType) -> None:
    """
    A long literal assigned to a secret-named variable is reported.

    This is the most common real leak: not a well-known token format, but a
    developer pasting a value straight into a settings module.
    """
    findings = _scan_line(scanner, HARDCODED_ASSIGNMENT)

    assert any("hardcoded-secret-value" in finding for finding in findings)


# ---------------------------------------------------------------------------
# Negative cases: the scanner must not flag correct configuration
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "line",
    [
        # A policy knob about a token, not the token.
        "ACCESS_TOKEN_EXPIRE_MINUTES=15",
        "REFRESH_TOKEN_DAYS=30",
        "REFRESH_TOKEN_ROTATION=true",
        "PASSWORD_MIN_LENGTH=12",
        "LLM_MAX_OUTPUT_TOKENS=1024",
        # An obvious placeholder in the documented example file.
        'JWT_SECRET_KEY="CHANGE_ME_generate_a_64_byte_random_secret"',
        # An empty value awaiting configuration.
        'S3_SECRET_ACCESS_KEY=""',
        # Reading a secret at runtime rather than embedding it.
        'password = os.environ["DATABASE_PASSWORD"]',
        "token = request.headers.get('authorization')",
        # A comment referring to a secret is not a secret.
        "# The JWT secret is read from JWT_SECRET_KEY.",
    ],
)
def test_correct_configuration_is_not_flagged(scanner: ModuleType, line: str) -> None:
    """
    The scanner must stay quiet on a settings file that is configured correctly.

    A false positive here is not harmless: it fails the build on valid work, and the
    usual response is to add an exemption or stop running the check — after which
    the genuine findings it would have caught are lost too.
    """
    findings = _scan_line(scanner, line)

    assert not findings, (
        f"the scanner flagged correct configuration {line!r}: {findings}. "
        "If this is a genuinely new secret-shaped setting, add the reason to the "
        "scanner's allowlist rather than deleting this test."
    )


def test_a_comment_is_never_scanned_as_an_assignment(scanner: ModuleType) -> None:
    """
    Commented-out examples must not fail the build.

    A developer commenting out a line that used to hold a placeholder is a normal
    edit, and failing the build for it teaches people to bypass the check.
    """
    assert not _scan_line(scanner, '# JWT_SECRET_KEY="CHANGE_ME_not_a_real_value"')


def test_findings_never_echo_the_secret(scanner: ModuleType) -> None:
    """
    A finding must identify the location without reproducing the credential.

    CI logs are frequently readable by more people than the repository is. A scanner
    that prints the secret converts a contained problem into a wider one, and the
    log then has to be treated as a secret itself.
    """
    secret = AWS_ACCESS_KEY_ID
    findings = _scan_line(scanner, f"AWS_KEY={secret}")

    assert findings, "the sample must be detected for this test to mean anything"
    assert all(secret not in finding for finding in findings), (
        "a finding reproduced the secret value; report the file, line and rule only"
    )


def test_the_live_repository_is_clean(scanner: ModuleType) -> None:
    """
    The scan passes on the repository as it stands.

    This is the assertion the build actually depends on, run here as well so that
    the scanner's own test run fails on a real leak rather than only ``make audit``.
    """
    findings = scanner.scan(scanner.tracked_files())
    findings += scanner.check_env_file()
    findings += scanner.check_env_example()

    assert not findings, "the repository contains findings:\n  " + "\n  ".join(findings)


def test_the_scanner_would_catch_a_leak_in_a_tracked_file(
    scanner: ModuleType, tmp_path: Path
) -> None:
    """
    End-to-end proof that a leak in a real file reaches a non-zero exit.

    The rule tests above call ``scan_text`` directly. This one drives the same path
    the build does — read the file, apply the rules, collect findings — so a mistake
    in the plumbing (a file skipped, a result dropped) cannot hide behind passing
    unit-level checks.
    """
    leaked = tmp_path / "leaked_settings.py"
    leaked.write_text(
        f"AWS_ACCESS_KEY_ID = '{AWS_ACCESS_KEY_ID}'\n{PRIVATE_KEY_HEADER}\n",
        encoding="utf-8",
    )

    findings = scanner.scan([leaked])

    assert len(findings) >= 2, f"expected both credential shapes to be reported: {findings}"
    assert all("leaked_settings.py" in finding for finding in findings)
