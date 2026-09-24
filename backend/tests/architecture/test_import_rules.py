"""
Structural rules about the codebase itself.

Documentation that is not tested rots. The architecture document states a module
dependency order and one absolute prohibition (production code must never import
the simulator); both are enforced here by parsing the import graph, so a violation
fails the build instead of surviving in a diagram nobody re-reads.

The rules are deliberately directional:

    core  <  db  <  models  <  repositories  <  services  <  api

A module may import from a layer at or below its own, never above. An upward
import is the first symptom of a cycle, and in this codebase it would typically
mean an entity reaching back into an HTTP concept.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

pytestmark = pytest.mark.architecture

BACKEND_ROOT = Path(__file__).resolve().parents[2]
APP_ROOT = BACKEND_ROOT / "app"

#: Layer index per top-level package under ``app.``. A lower index is "further
#: down" the stack; a module may import at its own level or lower.
LAYER: dict[str, int] = {
    "core": 0,
    "db": 1,
    "models": 2,
    "repositories": 3,
    "integrations": 3,
    "authorization": 3,
    "services": 4,
    "analytics": 4,
    "ai": 4,
    "telemetry": 4,
    "environment": 4,
    "reporting": 4,
    "notifications": 4,
    "optimization": 4,
    "classification": 4,
    "assistant": 4,
    "forecasting": 4,
    "anomaly": 4,
    "recommendations": 4,
    "tenancy": 4,
    "simulation": 5,
    "workers": 5,
    "api": 6,
    "scripts": 7,
}

#: Modules that compose the application and may therefore import from any layer.
COMPOSITION_ROOTS = {"main"}

#: Modules that sit *above* the layer map because they are the package itself
#: (``app``) or an entry point that owns no layer of its own.
#:
#: This is an explicit allowlist rather than a silent skip. Skipping any module
#: whose top-level package is unrecognised means a new top-level package — a whole
#: new bounded context, say — would be excluded from the layer rules without
#: anyone noticing, and the architecture test would keep passing while covering
#: less and less. ``test_every_module_is_layered_or_allowlisted`` fails instead.
UNLAYERED_MODULES = {"app", "app.main"}

#: Packages allowed to import ``app.simulation``. Everything else is forbidden:
#: production request handling must never be able to reach simulator code, which
#: would make simulated data indistinguishable from real data at the source
#: (master directive, sections 47 and 62).
SIMULATION_ALLOWED_IMPORTERS_PREFIXES = (
    "app.simulation",
    "app.workers",
    "app.scripts",
)


def _iter_modules() -> list[Path]:
    return sorted(path for path in APP_ROOT.rglob("*.py") if "__pycache__" not in path.parts)


def _module_name(path: Path) -> str:
    relative = path.relative_to(BACKEND_ROOT).with_suffix("")
    parts = list(relative.parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _imported_modules(path: Path) -> list[str]:
    """Absolute ``app.*`` modules imported by a file, including function-local ones."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except SyntaxError as exc:  # pragma: no cover - would fail collection anyway
        raise AssertionError(f"{path} is not valid Python: {exc}") from exc

    module_name = _module_name(path)
    package = module_name.rsplit(".", 1)[0] if "." in module_name else module_name

    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:  # relative import
                base = package
                for _ in range(node.level - 1):
                    base = base.rsplit(".", 1)[0] if "." in base else base
                target = f"{base}.{node.module}" if node.module else base
            else:
                target = node.module or ""
            if target:
                found.append(target)
                found.extend(f"{target}.{alias.name}" for alias in node.names)
    return [name for name in found if name == "app" or name.startswith("app.")]


def _top_level(name: str) -> str | None:
    parts = name.split(".")
    if len(parts) < 2 or parts[0] != "app":
        return None
    return parts[1]


ALL_MODULES = _iter_modules()


def test_the_application_package_has_modules() -> None:
    """Guard against a path change silently turning every rule into a no-op."""
    assert ALL_MODULES, f"no modules found under {APP_ROOT}"


def test_every_module_is_layered_or_allowlisted() -> None:
    """
    A module must belong to a layer, or be a deliberate, listed exception.

    Without this, a new top-level package is simply invisible to the layer rules
    and the architecture test keeps passing while silently covering less of the
    codebase. Adding a package is a normal event; discovering a year later that it
    was never covered is not.
    """
    unlayered = sorted(
        module
        for module in (_module_name(path) for path in ALL_MODULES)
        if module not in UNLAYERED_MODULES
        and (_top_level(module) is None or _top_level(module) not in LAYER)
    )

    assert not unlayered, (
        "These modules are neither in the layer map nor the unlayered allowlist, so "
        "the layer rules do not apply to them:\n  "
        + "\n  ".join(unlayered)
        + "\n\nAdd the top-level package to LAYER, or add the module to "
        "UNLAYERED_MODULES with a reason."
    )


@pytest.mark.parametrize("path", ALL_MODULES, ids=lambda p: _module_name(p))
def test_no_upward_layer_imports(path: Path) -> None:
    """
    A module may not import from a layer above its own.
    """
    module = _module_name(path)
    if module in COMPOSITION_ROOTS:
        pytest.skip("composition root; may import any layer by design")

    own_layer_name = _top_level(module)
    if own_layer_name is None or own_layer_name not in LAYER:
        # Reaching this point means the module is in UNLAYERED_MODULES, which
        # test_every_module_is_layered_or_allowlisted has already verified. A new
        # top-level package cannot slip through here.
        return

    own_layer = LAYER[own_layer_name]
    violations: list[str] = []

    for imported in _imported_modules(path):
        target_layer_name = _top_level(imported)
        if target_layer_name is None or target_layer_name not in LAYER:
            continue
        # An intra-package import (db.session from db.base) is always fine.
        if target_layer_name == own_layer_name:
            continue
        if LAYER[target_layer_name] > own_layer:
            violations.append(f"{module} ({own_layer_name}) -> {imported}")

    assert not violations, "upward layer imports detected:\n  " + "\n  ".join(violations)


@pytest.mark.parametrize("path", ALL_MODULES, ids=lambda p: _module_name(p))
def test_production_code_does_not_import_the_simulator(path: Path) -> None:
    """
    Nothing in the production path may import ``app.simulation``.

    The simulator generates plausible fake telemetry and fleet movement. If
    request handling could reach it, simulated data would become indistinguishable
    from real data at the point of origin, and no downstream provenance label
    could repair that.
    """
    module = _module_name(path)
    if module.startswith(SIMULATION_ALLOWED_IMPORTERS_PREFIXES):
        pytest.skip("simulator, worker or script; permitted to use simulation")

    offenders = [
        imported
        for imported in _imported_modules(path)
        if imported == "app.simulation" or imported.startswith("app.simulation.")
    ]

    assert not offenders, (
        f"{module} imports the simulator ({offenders}). Production code must not "
        "depend on simulated data; wire it through a provider interface instead."
    )


@pytest.mark.parametrize("path", ALL_MODULES, ids=lambda p: _module_name(p))
def test_application_code_does_not_import_tests(path: Path) -> None:
    """No application module may depend on the test suite."""
    offenders = [
        imported
        for imported in _imported_modules(path)
        if imported == "tests" or imported.startswith("tests.")
    ]

    assert not offenders, f"{_module_name(path)} imports test code: {offenders}"


def test_core_has_no_infrastructure_dependencies() -> None:
    """
    ``app.core`` is the bottom of the graph.

    It may not import the database, models, services or API. Allowing it would
    make the configuration and error modules depend on the persistence layer,
    which is how a startup-time import cycle begins.
    """
    core_dir = APP_ROOT / "core"
    violations: list[str] = []

    for path in sorted(core_dir.glob("*.py")):
        for imported in _imported_modules(path):
            target = _top_level(imported)
            if target in {"db", "models", "repositories", "services", "api", "workers"}:
                violations.append(f"{_module_name(path)} -> {imported}")

    assert not violations, "app.core must stay infrastructure-free:\n  " + "\n  ".join(violations)


def test_models_do_not_import_repositories_or_services() -> None:
    """
    Entities must not depend on the code that queries them.

    A model importing a repository creates a cycle the moment the repository
    imports the model — which it always does.
    """
    models_dir = APP_ROOT / "models"
    violations: list[str] = []

    for path in sorted(models_dir.glob("*.py")):
        for imported in _imported_modules(path):
            target = _top_level(imported)
            if target in {"repositories", "services", "api"}:
                violations.append(f"{_module_name(path)} -> {imported}")

    assert not violations, "models must not import repositories/services/api:\n  " + "\n  ".join(
        violations
    )


def test_migrations_do_not_import_application_services() -> None:
    """
    A migration must depend only on SQL and metadata, never on application code.

    A migration that imports a service would break as soon as that service
    changed, making historical migrations unrunnable — and an unrunnable
    migration cannot be used to restore a database.
    """
    versions_dir = BACKEND_ROOT / "migrations" / "versions"
    violations: list[str] = []

    for path in sorted(versions_dir.glob("*.py")):
        for imported in _imported_modules(path):
            target = _top_level(imported)
            if target in {"services", "repositories", "api", "workers", "analytics", "ai"}:
                violations.append(f"{path.name} -> {imported}")

    assert not violations, "migrations must not depend on application code:\n  " + "\n  ".join(
        violations
    )
