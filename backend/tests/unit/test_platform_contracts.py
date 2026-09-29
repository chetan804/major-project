"""Control-plane validation and bootstrap terminal policy without a database."""

from types import SimpleNamespace

import pytest

from app.core.errors import InputValidationError
from app.scripts import bootstrap_operator
from app.services.platform_tenants import (
    validate_metadata,
    validate_operator_email,
    validate_operator_reason,
)

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "value",
    [
        "",
        "not-a-mailbox",
        "a@",
        "@host.test",
        "name <a@host.test>",
        "a@host.test,b@host.test",
        "a\r\nb@host.test",
        "a\x7f@host.test",
        "a@@host.test",
        "é@host.test",
        "(unclosed@host.test",
    ],
)
def test_email_rejects_unsafe_or_multiple_mailboxes(value):
    with pytest.raises(InputValidationError):
        validate_operator_email(value)


def test_operator_inputs_have_bounded_normalization():
    assert validate_operator_email(" Operator@Example.test ") == "operator@example.test"
    assert validate_operator_reason("  Approved change  ") == "Approved change"
    validate_metadata({"name": "Amsterdam", "timezone": "Europe/Amsterdam", "locale": "nl-NL"})
    for values in (
        {"tenant_id": "foreign"},
        {"name": None},
        {"timezone": "No/Place"},
        {"locale": "bad locale"},
        {"name": "x" * 201},
    ):
        with pytest.raises(InputValidationError):
            validate_metadata(values)
    for value in ("short", " " * 10, "x" * 1001):
        with pytest.raises(InputValidationError):
            validate_operator_reason(value)


def test_bootstrap_cli_refuses_noninteractive_input(monkeypatch):
    monkeypatch.setattr(
        "sys.argv",
        [
            "bootstrap_operator",
            "--email",
            "operator@example.test",
            "--name",
            "Operator",
            "--reason",
            "Approved bootstrap",
        ],
    )
    monkeypatch.setattr("sys.stdin", SimpleNamespace(isatty=lambda: False))

    def must_not_prompt(*args):
        raise AssertionError("must refuse before reading passwords or touching DB")

    monkeypatch.setattr(bootstrap_operator.getpass, "getpass", must_not_prompt)
    with pytest.raises(SystemExit) as error:
        bootstrap_operator.main()
    assert error.value.code == 2


def test_bootstrap_cli_refuses_echo_fallback(monkeypatch):
    import warnings

    monkeypatch.setattr(
        "sys.argv",
        [
            "bootstrap_operator",
            "--email",
            "operator@example.test",
            "--name",
            "Operator",
            "--reason",
            "Approved bootstrap",
        ],
    )
    monkeypatch.setattr("sys.stdin", SimpleNamespace(isatty=lambda: True))

    def unsafe_prompt(*args):
        warnings.warn(
            "Cannot disable echo", bootstrap_operator.getpass.GetPassWarning, stacklevel=2
        )
        raise AssertionError("warning must stop any password input")

    monkeypatch.setattr(bootstrap_operator.getpass, "getpass", unsafe_prompt)
    with pytest.raises(SystemExit) as error:
        bootstrap_operator.main()
    assert error.value.code == 2
