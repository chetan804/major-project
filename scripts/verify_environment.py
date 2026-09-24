#!/usr/bin/env python3
"""
Report what this environment can actually do.

The master directive forbids presenting unavailable infrastructure as working
(sections 47, 62). The honest way to honour that is to measure the environment and
say so, which is what this script does: for each component the platform needs it
reports REAL, SIMULATED, or MISSING, and names the consequence.

It is deliberately not a health check of the running application — that is
``/ready``. This answers a different question, asked before the application exists:
*can this machine run the thing I am about to build?*

Exits non-zero only when a component the application cannot start without is
missing. An absent optional service is reported and does not fail, because
development on a laptop without Redis is a supported configuration.
"""

from __future__ import annotations

import importlib.metadata
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

REAL = "REAL"
SIMULATED = "SIMULATED"
MISSING = "MISSING"


@dataclass
class Finding:
    component: str
    status: str
    detail: str
    consequence: str = ""


def _version(distribution: str) -> str | None:
    try:
        return importlib.metadata.version(distribution)
    except importlib.metadata.PackageNotFoundError:
        return None


def check_python() -> Finding:
    version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    if sys.version_info < (3, 11):
        return Finding(
            "Python",
            MISSING,
            f"{version} (3.11+ required)",
            "The application uses StrEnum, Self and tomllib, all of which need 3.11.",
        )
    return Finding("Python", REAL, version)


def check_postgres() -> Finding:
    """
    Whether a real PostgreSQL server is reachable through the bundled binaries.

    Checked by starting (or attaching to) the local cluster through the same helper
    the application and tests use, so a positive result means the real path works
    rather than that a binary exists somewhere on disk.
    """
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    try:
        import pg_server  # noqa: PLC0415

        server = pg_server._server()
        version = server.psql("SHOW server_version;").strip().splitlines()
        major = version[2].split(".")[0].strip() if len(version) > 2 else "?"
        return Finding(
            "PostgreSQL",
            REAL,
            f"{major} at {pg_server._socket_dir()}",
        )
    except Exception as exc:  # noqa: BLE001 - any failure means "not usable"
        return Finding(
            "PostgreSQL",
            MISSING,
            f"cluster unavailable: {type(exc).__name__}",
            "Required. There is no SQLite fallback: constraints, NUMERIC precision "
            "and row-level security must be real (ADR-0002). Run ./scripts/bootstrap.sh.",
        )


def check_postgis() -> Finding:
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    try:
        import pg_server  # noqa: PLC0415

        out = pg_server._server().psql(
            "SELECT count(*) FROM pg_available_extensions WHERE name = 'postgis';"
        )
        available = "1" in out.split("\n")[2] if len(out.split("\n")) > 2 else False
    except Exception:  # noqa: BLE001
        available = False

    if available:
        return Finding("PostGIS", REAL, "extension available")
    return Finding(
        "PostGIS",
        MISSING,
        "not installed in this cluster",
        "Geospatial queries use a dialect-aware fallback: real PostGIS when present, "
        "documented numeric bounds otherwise (ADR-0005). Map features must state "
        "which is in use.",
    )


def check_redis() -> Finding:
    """Real Redis if a server responds, otherwise the in-process substitute."""
    import socket

    for host, port in (("127.0.0.1", 6379), ("localhost", 6379)):
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return Finding("Redis", REAL, f"responding on {host}:{port}")
        except OSError:
            continue

    if _version("fakeredis"):
        return Finding(
            "Redis",
            SIMULATED,
            f"fakeredis {_version('fakeredis')} (in-process)",
            "Cache and rate-limit state are process-local and reset on restart. The "
            "cache health check reports is_simulated=true, and responses that depend "
            "on it are labelled accordingly.",
        )
    return Finding(
        "Redis",
        MISSING,
        "no server and no fakeredis",
        "The cache layer degrades to a no-op; /ready reports it as a warning without "
        "failing, because a cache is not required for correctness.",
    )


def check_docker() -> Finding:
    if shutil.which("docker") is None:
        return Finding(
            "Docker",
            MISSING,
            "not installed",
            "Compose and Dockerfiles are authored but cannot be built or run here. "
            "Container images are therefore unverified in this environment.",
        )
    return Finding("Docker", REAL, "docker CLI present")


def check_importable(
    component: str, module_name: str, distribution: str, note: str
) -> Finding:
    """
    Whether a dependency is importable, checked by importing it.

    The import name and the distribution name frequently differ — the vision
    package installs ``cv2`` but its distribution is ``opencv-python-headless``, not
    ``opencv-python``. Checking the distribution name reported a correctly installed
    dependency as missing, which is the same class of error as reporting a missing
    one as present: both make the report untrustworthy. ``find_spec`` resolves the
    import name the code will actually use.
    """
    import importlib.util

    if importlib.util.find_spec(module_name) is None:
        return Finding(component, MISSING, f"{module_name} not importable", note)

    version = _version(distribution)
    detail = f"{module_name} {version}" if version else f"{module_name} (version unknown)"
    return Finding(component, REAL, detail)


def check_gpu() -> Finding:
    """Whether a CUDA-capable device is present, for the vision workload."""
    try:
        import torch  # noqa: PLC0415

        if torch.cuda.is_available():
            return Finding("GPU", REAL, torch.cuda.get_device_name(0))
        return Finding(
            "GPU",
            MISSING,
            "torch installed, no CUDA device",
            "Vision inference runs on CPU. Training is out of scope here, which is why "
            "no accuracy figure for any classifier is claimed (ADR-0008).",
        )
    except ImportError:
        return Finding(
            "GPU",
            MISSING,
            "no torch, no CUDA",
            "Expected. The vision stack uses classical OpenCV methods rather than a "
            "deep model, so no GPU is required (ADR-0008).",
        )


def collect() -> list[Finding]:
    return [
        check_python(),
        check_postgres(),
        check_postgis(),
        check_redis(),
        check_docker(),
        check_gpu(),
        check_importable(
            "Routing optimiser",
            "ortools",
            "ortools",
            "Route optimisation cannot run. It is deterministic and required for "
            "collection planning (ADR-0007), so this blocks Phase 6, not startup.",
        ),
        check_importable(
            "Classical ML",
            "sklearn",
            "scikit-learn",
            "Forecasting and anomaly detection cannot run (Phases 8 and 9).",
        ),
        check_importable("Data frames", "pandas", "pandas", "Batch analytics unavailable."),
        check_importable("Numerics", "numpy", "numpy", "Numerical support unavailable."),
        check_importable(
            "Vision",
            "cv2",
            "opencv-python-headless",
            "Waste image classification unavailable. Reported accuracy for the "
            "classifier would be unsupportable without it (ADR-0008).",
        ),
        check_importable("Task queue", "celery", "celery", "Background jobs unavailable."),
    ]


def main() -> int:
    findings = collect()

    width = max(len(f.component) for f in findings) + 2
    print("EcoMind-AI environment")
    print("=" * 78)
    for finding in findings:
        print(f"{finding.component:<{width}} {finding.status:<10} {finding.detail}")

    consequences = [f for f in findings if f.consequence]
    if consequences:
        print()
        print("What the missing or substituted components mean")
        print("-" * 78)
        for finding in consequences:
            print(f"  {finding.component}: {finding.consequence}")

    blocking = [
        f for f in findings if f.status == MISSING and f.component in {"Python", "PostgreSQL"}
    ]
    print()
    if blocking:
        print("RESULT: this environment cannot run the application.")
        for finding in blocking:
            print(f"  - {finding.component}: {finding.detail}")
        return 1

    simulated = [f.component for f in findings if f.status == SIMULATED]
    real = [f.component for f in findings if f.status == REAL]
    print(f"RESULT: usable. {len(real)} real, {len(simulated)} simulated.")
    if simulated:
        # Named explicitly, every time. A reader must never have to infer which
        # parts of a running system are not real (ADR-0013).
        print("Simulated components: " + ", ".join(simulated))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
