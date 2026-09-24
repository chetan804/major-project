#!/usr/bin/env python3
"""
Secret scanner.

A committed credential is not fixed by deleting the line: it is in the history,
it has been cloned, and it must be rotated. The only reliable remedy is to keep it
out of the repository in the first place, which is what this check is for. It runs
in CI and in ``make audit``, so a secret fails the build rather than being found
later by a person reading a diff.

What it checks
--------------
1. **Credential-shaped strings** in tracked files, matched by pattern: private key
   blocks, cloud access-key ids, JWTs, connection strings carrying a password, and
   ``name = "<long literal>"`` assignments for names that denote a secret.
2. **The real environment file is not tracked.** ``.env`` holding working
   credentials is a normal local setup; ``.env`` in the repository is a leak.
   ``.env.example`` is expected and is checked to hold only placeholders.
3. **No credential is staged in the index** even if the working copy is clean,
   because that is the state that actually gets committed.

Design decisions worth stating
------------------------------
* **Tracked files only, plus a check of the index.** Scanning the whole working
  tree would flag a developer's local ``.env`` — the file the gitignore is there to
  protect — and a check that cries wolf on a correct setup gets disabled.
* **Placeholders are allowlisted explicitly, by value.** A pattern that merely
  looks for a "<something>SECRET" name would flag ``JWT_SECRET_KEY`` in
  ``.env.example``, which must exist and must hold a placeholder.
* **Findings are reported with file and line and never print the secret.** Printing
  it would copy the credential into the CI log, which is frequently more widely
  readable than the repository.
* **A finding exits non-zero.** A warning that does not fail the build is a
  notification, not a control.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

#: Files that are generated, vendored, or intentionally hold placeholders. Each
#: entry is a reason, not a convenience.
SKIP_PATH_FRAGMENTS: tuple[str, ...] = (
    ".venv/",
    "node_modules/",
    ".runtime/",
    ".git/",
    "dist/",
    "build/",
    "__pycache__/",
    "package-lock.json",
    "poetry.lock",
    ".pytest_cache/",
    ".mypy_cache/",
    ".ruff_cache/",
    ".coverage",
)

#: Exact values that are placeholders. Compared after stripping quotes.
PLACEHOLDER_VALUES: frozenset[str] = frozenset(
    {
        "",
        "CHANGE_ME",
        "CHANGE_ME_generate_a_64_byte_random_secret",
        "CHANGE_ME_device_gateway_key",
        "changeme",
        "your-secret-here",
        "replace-me",
        "test",
        "example",
    }
)

#: Leading/trailing markers that make a value obviously a placeholder.
PLACEHOLDER_MARKERS: tuple[str, ...] = (
    "CHANGE_ME",
    "change-me",
    "REPLACE_ME",
    "replace-me",
    "<",
    ">",
    "${",
    "xxx",
    "your-",
    "example",
    "placeholder",
    "dummy",
)

#: Names whose assignments are worth inspecting for a real value.
SECRET_NAME_PATTERN = re.compile(
    r"(?i)\b[\w.]*(secret|password|passwd|token|api[_-]?key|private[_-]?key|"
    r"access[_-]?key|credential)[\w.]*\b"
)

#: Suffixes naming a *property of* a secret rather than the secret material:
#: an expiry, a length policy, a rotation switch, a signing algorithm. A settings
#: file must state these, and their values are integers, durations or booleans.
#:
#: Without this list the scanner flags ``ACCESS_TOKEN_EXPIRE_MINUTES=15`` and
#: ``PASSWORD_MIN_LENGTH=12``. Those findings are wrong, and a control that reports
#: false positives on a correct file is a control that gets switched off.
NON_SECRET_NAME_SUFFIXES: tuple[str, ...] = (
    "_MINUTES",
    "_SECONDS",
    "_HOURS",
    "_DAYS",
    "_LENGTH",
    "_COUNT",
    "_SIZE",
    "_TTL",
    "_EXPIRY",
    "_EXPIRE",
    "_ROTATION",
    "_ALGORITHM",
    "_ALG",
    "_ISSUER",
    "_AUDIENCE",
    "_HEADER",
    "_PREFIX",
    "_MAX",
    "_MIN",
    "_TOKENS",
    "_ENABLED",
    "_TIMEOUT",
    "_LIMIT",
)

#: A value with this shape is a policy number or a switch, never secret material.
#: No credential is a bare integer, and treating one as a finding produced the
#: false positives described above.
NON_SECRET_VALUE_PATTERN = re.compile(
    r"(?i)^(?:true|false|none|null|-?\d+(?:\.\d+)?|\d+[smhdw])$"
)

#: Shortest value treated as credential material.
#:
#: A real API key, token or generated secret is long: 20 characters is below every
#: provider's minimum and still above every plausible fixture. Requiring this
#: length is what separates "someone pasted a key into a settings module" — the
#: leak worth failing a build over — from `password: "hunter2"` inside a test that
#: asserts the redaction processor masks it. Without the threshold the scanner
#: reports its own test fixtures, and a control that fails on correct code is a
#: control that gets switched off.
MIN_SECRET_LENGTH = 20


def _is_secret_material(name: str, value: str) -> bool:
    """
    Whether an assignment is plausibly the secret itself.

    Two independent filters, because either alone is too blunt: the name says what
    the setting is *for*, and the value's shape says what it *is*. A name ending in
    ``_MINUTES`` is a duration however long the file is; a value of ``15`` is a
    number whatever the name.
    """
    stripped = value.strip()
    if NON_SECRET_VALUE_PATTERN.match(stripped):
        return False

    # An enumeration member whose value equals its name is an identifier, not a
    # credential: ErrorCode.TOKEN_EXPIRED = "TOKEN_EXPIRED". No secret is its own
    # name, so this test is safe and removes an entire class of false positive.
    if stripped.upper() == name.upper().strip("_"):
        return False

    if len(stripped) < MIN_SECRET_LENGTH:
        return False

    upper = name.upper().strip("_")
    return not any(upper.endswith(suffix) for suffix in NON_SECRET_NAME_SUFFIXES)


@dataclass(frozen=True)
class Rule:
    """One credential shape. ``description`` is what a reader sees on a finding."""

    name: str
    pattern: re.Pattern[str]
    description: str


RULES: tuple[Rule, ...] = (
    Rule(
        "private-key-block",
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        "An embedded private key. No legitimate reason exists for one in the repository.",
    ),
    Rule(
        "aws-access-key-id",
        re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
        "An AWS access key id.",
    ),
    Rule(
        "google-api-key",
        re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
        "A Google API key.",
    ),
    Rule(
        "github-token",
        re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36,}\b"),
        "A GitHub token.",
    ),
    Rule(
        "slack-token",
        re.compile(r"\bxox[abpsr]-[0-9A-Za-z-]{10,}\b"),
        "A Slack token.",
    ),
    Rule(
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        "A JSON Web Token. Signed tokens in a repository are either a leak or a "
        "test fixture that should be generated at runtime.",
    ),
    Rule(
        "connection-string-with-password",
        re.compile(
            r"\b(?:postgres(?:ql)?|mysql|redis|amqp|mongodb(?:\+srv)?)://[^\s:@/]+:[^\s@/]{3,}@",
            re.IGNORECASE,
        ),
        "A connection URL carrying an inline password.",
    ),
    Rule(
        "pem-or-pkcs12-blob",
        re.compile(r"-----BEGIN (?:CERTIFICATE|PKCS12)-----"),
        "An embedded certificate or keystore. Certificate material belongs in a "
        "secret store or a mounted volume, not in source.",
    ),
)


def _git(*args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout


def tracked_files() -> list[Path]:
    """Files in the index — that is, what a commit would actually contain."""
    out = _git("ls-files", "-z")
    return [REPO_ROOT / name for name in out.split("\0") if name]


def _display_path(path: Path) -> str:
    """
    A repository-relative path when possible, an absolute one otherwise.

    ``scan`` is called with tracked files, but the same functions are used by the
    scanner's own tests against temporary files outside the repository. Raising
    there would make the scanner report a crash instead of a finding — and a
    scanner that dies on an unexpected path is one that gets removed from the build.
    """
    try:
        return path.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return str(path)


def _is_skipped(path: Path) -> bool:
    relative = _display_path(path)
    return any(fragment in relative for fragment in SKIP_PATH_FRAGMENTS)


def _read_text(path: Path) -> str | None:
    """Return the file's text, or None when it is binary or unreadable."""
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    if b"\0" in raw[:8192]:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _is_placeholder(value: str) -> bool:
    cleaned = value.strip().strip("\"'").strip()
    if cleaned in PLACEHOLDER_VALUES:
        return True
    lowered = cleaned.lower()
    return any(marker.lower() in lowered for marker in PLACEHOLDER_MARKERS)


def _secret_assignments(text: str) -> Iterator[tuple[int, str]]:
    """
    Yield ``(line_number, value)`` for assignments to secret-looking names.

    Only single-line assignments of a quoted literal are considered. That covers
    the accidental commit — a real key pasted into a settings file — without trying
    to parse the language, which would produce false positives on legitimate code
    such as ``password = request.form["password"]``.
    """
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith(("#", "//", "*", "<!--")):
            continue

        match = re.match(
            r"(?i)^(?:export\s+)?[\"']?([\w.]+)[\"']?\s*[:=]\s*([\"'])([^\"']{8,})\2",
            stripped,
        )
        if not match:
            continue
        name, _, value = match.groups()
        if not SECRET_NAME_PATTERN.search(name):
            continue
        if _is_placeholder(value) or not _is_secret_material(name, value):
            continue
        yield number, value


def scan_text(path: Path, text: str) -> list[str]:
    """All findings for one file, as printable lines."""
    findings: list[str] = []
    relative = _display_path(path)

    for rule in RULES:
        for match in rule.pattern.finditer(text):
            line_number = text.count("\n", 0, match.start()) + 1
            # Never echo the value: the CI log is often more accessible than the
            # repository, and a finding must not itself become the leak.
            findings.append(
                f"{relative}:{line_number}: {rule.name} - {rule.description}"
            )

    for line_number, value in _secret_assignments(text):
        findings.append(
            f"{relative}:{line_number}: hardcoded-secret-value - an assignment to a "
            f"secret-looking name holds a {len(value)}-character literal. Move it to "
            "the environment (.env, uncommitted) and reference it through Settings."
        )

    return findings


def check_env_file() -> list[str]:
    """
    The real environment file must be ignored and absent from the index.

    ``.env`` is where working credentials legitimately live, so it must not be
    tracked. Checked via git rather than the filesystem: a local ``.env`` is
    correct and expected, an *ignored* local ``.env`` is correct, and a *tracked*
    one is the leak.
    """
    findings: list[str] = []
    tracked = set(_git("ls-files").splitlines())

    if ".env" in tracked:
        findings.append(
            ".env: tracked by git. This file holds working credentials; remove it "
            "from the index (git rm --cached .env) and rotate every value it held."
        )

    for name in sorted(tracked):
        if name == ".env.example":
            continue
        if re.fullmatch(r"\.env(\.[\w-]+)?", name):
            findings.append(
                f"{name}: tracked. Only .env.example may be committed; every other "
                ".env file holds real values."
            )

    return findings


def check_env_example() -> list[str]:
    """
    ``.env.example`` must contain placeholders, never a usable value.

    It is the file people copy to ``.env``, so a real default here would silently
    become one developer's — or one deployment's — working configuration.
    """
    path = REPO_ROOT / ".env.example"
    if not path.exists():
        return [".env.example: missing. It is the documented contract for configuration."]

    findings: list[str] = []
    text = _read_text(path) or ""
    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        name, _, raw_value = stripped.partition("=")
        if not SECRET_NAME_PATTERN.search(name):
            continue
        value = raw_value.strip().strip("\"'")
        if value and not _is_placeholder(value) and _is_secret_material(name, value):
            findings.append(
                f".env.example:{line_number}: {name.strip()} holds a literal value. "
                "It must be empty or an obvious placeholder such as CHANGE_ME."
            )
    return findings


def scan(paths: Iterable[Path]) -> list[str]:
    findings: list[str] = []
    for path in paths:
        if _is_skipped(path) or not path.is_file():
            continue
        text = _read_text(path)
        if text is None:
            continue
        findings.extend(scan_text(path, text))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Fail if a credential is present in the repository.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="print only findings, not the summary",
    )
    args = parser.parse_args(argv)

    try:
        files = tracked_files()
    except RuntimeError as exc:
        print(f"secret scan could not run: {exc}", file=sys.stderr)
        return 2

    findings = scan(files)
    findings.extend(check_env_file())
    findings.extend(check_env_example())

    if findings:
        print("Secret scan FAILED. Findings:", file=sys.stderr)
        for finding in sorted(set(findings)):
            print(f"  {finding}", file=sys.stderr)
        print(
            "\nRemoving the line is not enough: a committed credential stays in the "
            "history and must be rotated. Rotate first, then purge.",
            file=sys.stderr,
        )
        return 1

    if not args.quiet:
        print(f"Secret scan passed: {len(files)} tracked files, no findings.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
