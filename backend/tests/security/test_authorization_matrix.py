"""
The authorization matrix test: the seeded roles must match ``rbac.md`` §4.

``rbac.md`` is the source of truth for who may do what. This test reads that
document's matrix table and compares it, cell by cell, against the resolved
permission sets in :mod:`app.authorization.role_matrix`. It is the reason the
matrix can be *derived* from a table rather than hand-written per role: a
hand-written set drifted from the document in twenty-one places, and every one
of those was a silent change to who could read or write a tenant's data.

The document is parsed rather than duplicated here on purpose. A copy in the
test would agree with the code and disagree with the document, which is the same
failure with extra steps.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.authorization.permissions import PERMISSIONS, PLATFORM_PERMISSION_CODES
from app.authorization.role_matrix import (
    GRANTS,
    ROLE_DEFINITIONS,
    ROLE_PERMISSION_MAP,
    permissions_for_role,
)

#: The specification this module is checked against. Resolved from the repository
#: root rather than a relative path so the test behaves identically whether it is
#: run from ``backend/``, from the repository root, or from a checkout elsewhere
#: on disk.
RBAC_DOC = Path(__file__).resolve()
for _candidate in [RBAC_DOC, *RBAC_DOC.parents]:
    if (_candidate / "docs" / "security" / "rbac.md").is_file():
        RBAC_DOC = _candidate / "docs" / "security" / "rbac.md"
        break
else:  # pragma: no cover - only when the repository is incomplete
    raise RuntimeError("could not locate docs/security/rbac.md above the test file")

#: The document's column order.
ROLE_COLUMNS = (
    "SUPER_ADMIN",
    "TENANT_ADMIN",
    "OPERATIONS_MANAGER",
    "DISPATCHER",
    "DRIVER",
    "FIELD_WORKER",
    "FACILITY_MANAGER",
    "ANALYST",
    "SUSTAINABILITY_MANAGER",
    "VIEWER",
)

#: Families the document writes as "a / b" where the second part is not a code
#: on its own. Kept here rather than in the matrix module so the module stays a
#: plain table of marks.
FAMILY_ALIASES: dict[str, tuple[str, ...]] = {
    "sessions.read / revoke": ("sessions.read", "sessions.revoke"),
    "alerts.acknowledge / resolve": ("alerts.acknowledge", "alerts.resolve"),
    "routes.create / update": ("routes.create", "routes.update"),
    "routes.assign / dispatch": ("routes.assign", "routes.dispatch"),
    "vehicles.write / delete": ("vehicles.write", "vehicles.delete"),
    "drivers.write / assignments.write": ("drivers.write", "drivers.assignments.write"),
    "facilities.write / capacity.write": (
        "facilities.write",
        "facilities.capacity.write",
    ),
    "loads.create / update": ("loads.create", "loads.update"),
    "files.upload / files.read.own": ("files.upload", "files.read.own"),
}


def _document_rows() -> list[tuple[str, tuple[str, ...]]]:
    """The ``rbac.md`` §4 matrix as ``(family, marks)`` pairs."""
    rows: list[tuple[str, tuple[str, ...]]] = []
    in_matrix = False
    for line in RBAC_DOC.read_text(encoding="utf-8").splitlines():
        if line.startswith("## 4."):
            in_matrix = True
            continue
        if in_matrix and line.startswith("## "):
            break
        if not in_matrix or not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) != len(ROLE_COLUMNS) + 1:
            continue
        if cells[0] == "Permission family" or set(cells[1:]) <= {"---"}:
            continue
        rows.append((cells[0], tuple(cells[1:])))
    return rows


def _expand(family: str) -> tuple[str, ...]:
    """The permission codes a document family covers."""
    if family in FAMILY_ALIASES:
        return FAMILY_ALIASES[family]
    if family == "apikeys.*":
        return tuple(sorted(code for code in PERMISSIONS if code.startswith("apikeys.")))
    if family == "platform.*":
        return tuple(sorted(PLATFORM_PERMISSION_CODES))
    if family in PERMISSIONS:
        return (family,)
    if f"{family}.own" in PERMISSIONS:
        return (f"{family}.own",)
    raise AssertionError(f"unknown permission family in rbac.md: {family!r}")


DOCUMENT_ROWS = _document_rows()


def test_the_document_matrix_was_found() -> None:
    """
    Guard against a silent empty comparison.

    If the document is moved or its table is reformatted, ``_document_rows``
    returns nothing and every assertion below would pass vacuously. This test
    fails instead, so a parsing regression cannot masquerade as compliance.
    """
    assert len(DOCUMENT_ROWS) >= 60, (
        f"only {len(DOCUMENT_ROWS)} permission families parsed from rbac.md; "
        "the matrix table may have moved"
    )


@pytest.mark.parametrize(("family", "marks"), DOCUMENT_ROWS, ids=[row[0] for row in DOCUMENT_ROWS])
def test_family_matches_the_document(family: str, marks: tuple[str, ...]) -> None:
    """One row of the matrix, checked against every role it names."""
    codes = _expand(family)
    assert codes, f"family {family!r} expands to no permission codes"

    for role, mark in zip(ROLE_COLUMNS, marks, strict=True):
        granted = ROLE_PERMISSION_MAP[role]
        if mark == "\u2714":
            for code in codes:
                assert code in granted, f"{role} must hold {code} ({family})"
        elif mark == "o":
            for code in codes:
                own = f"{code}.own"
                if own in PERMISSIONS:
                    assert own in granted, f"{role} must hold {own} ({family}, own scope)"
                assert code not in granted, f"{role} holds {code} but {family} is own-scope only"
        else:
            assert mark == "\u2013", f"unexpected mark {mark!r} for {family}"
            for code in codes:
                assert code not in granted, f"{role} must not hold {code} ({family})"


def test_matrix_covers_every_role_column() -> None:
    """A role named in the document but missing from the matrix is unseedable."""
    assert set(GRANTS) == set(ROLE_COLUMNS)
    assert set(ROLE_DEFINITIONS) == set(ROLE_COLUMNS)


def test_every_granted_code_exists_in_the_catalogue() -> None:
    """
    A code that is not in the catalogue can never be checked, so granting it is
    a silent widening of the role.
    """
    for role, codes in ROLE_PERMISSION_MAP.items():
        unknown = sorted(codes - set(PERMISSIONS))
        assert not unknown, f"{role} grants codes absent from the catalogue: {unknown}"


def test_deliberate_omissions_are_still_omitted() -> None:
    """
    The two omissions ``rbac.md`` §4.1 calls out explicitly.

    They look like mistakes when reading the matrix, which is exactly why they
    are asserted: someone "fixing" them would remove the platform boundary
    between a tenant and model promotion, or let a browser session forge
    telemetry.
    """
    for role in ROLE_COLUMNS:
        if role == "SUPER_ADMIN":
            # The platform equivalent is what a platform operator holds.
            assert "platform.models.manage" in ROLE_PERMISSION_MAP[role]
        assert "models.manage" not in ROLE_PERMISSION_MAP[role], (
            f"{role} holds models.manage; model promotion is a platform action"
        )
        assert "bins.telemetry.ingest" not in ROLE_PERMISSION_MAP[role], (
            f"{role} holds bins.telemetry.ingest; telemetry ingest is device-only"
        )


def test_unknown_role_grants_nothing() -> None:
    """A stale role code must deny everything rather than raise on every request."""
    assert permissions_for_role("NO_SUCH_ROLE") == frozenset()


def test_role_levels_are_ordered() -> None:
    """Levels order the role picker and escalation checks; they must not collide."""
    levels = [role.level for role in ROLE_DEFINITIONS.values()]
    assert len(set(levels)) == len(levels)


def test_exactly_one_default_role() -> None:
    """Two defaults would grant every new member two bundles of permissions."""
    defaults = [role.code for role in ROLE_DEFINITIONS.values() if role.is_default]
    assert defaults == ["VIEWER"]


def test_matrix_module_table_matches_the_document_row_count() -> None:
    """The matrix table and the document must describe the same set of families."""
    from app.authorization.role_matrix import FAMILIES

    assert len(FAMILIES) == len(DOCUMENT_ROWS)
    for (family, _marks), (doc_family, _doc_marks) in zip(FAMILIES, DOCUMENT_ROWS, strict=True):
        assert family == doc_family, "the matrix table's family order drifted from rbac.md"


def test_driver_sees_only_own_records() -> None:
    """
    ``rbac.md`` §4.1: a driver's app returns only their own stops.

    Asserted as a whole rather than per code, because the intent is that the
    driver role holds *no* tenant-wide read of the operational record.
    """
    driver = ROLE_PERMISSION_MAP["DRIVER"]
    for tenant_wide in (
        "bins.read",
        "collections.read",
        "routes.read",
        "loads.read",
        "alerts.read",
        "vehicles.read",
    ):
        assert tenant_wide not in driver
        assert f"{tenant_wide}.own" in driver


def test_viewer_is_read_only() -> None:
    """``rbac.md`` §4.1: read-only means read-only, including no export."""
    viewer = ROLE_PERMISSION_MAP["VIEWER"]
    for write_code in sorted(
        code
        for code in PERMISSIONS
        if code.endswith(
            (
                ".write",
                ".create",
                ".delete",
                ".ingest",
                ".optimize",
                ".act",
                ".manage",
                ".configure",
                ".export",
                ".import",
                ".assign",
                ".dispatch",
                ".record",
                ".complete.own",
            )
        )
    ):
        assert write_code not in viewer, f"VIEWER holds {write_code}"
    assert "analytics.export" not in viewer
    assert "data.export" not in viewer
    assert not any(code.startswith("reports.") and code != "reports.read" for code in viewer)


def test_matrix_codes_are_stable_identifiers() -> None:
    """Codes appear in URLs, audit rows and the frontend; they must stay tidy."""
    for code in PERMISSIONS:
        assert re.fullmatch(r"[a-z][a-z0-9_]*(\.[a-z0-9_]+)*", code), code
