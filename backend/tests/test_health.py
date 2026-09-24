"""Liveness, readiness and metrics endpoint behaviour."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.api


async def test_health_is_ok_without_touching_dependencies(client) -> None:
    """
    Liveness must not perform I/O.

    If it depended on the database, a brief database outage would cause every API
    container to be restarted at once, converting a recoverable dependency
    failure into a full outage. This test asserts the response shape a probe
    depends on rather than trying to prove the absence of I/O — that absence is
    enforced by the handler containing no dependency injection.
    """
    response = await client.get("/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["app"] == "EcoMind-AI"
    assert body["environment"] == "test"
    assert isinstance(body["uptime_seconds"], (int, float))
    assert body["timestamp"].endswith("Z")


async def test_health_reports_adapter_identity_and_simulation(client) -> None:
    """
    Every pluggable component states which implementation is live.

    ADR-0013 requires that a reader can never mistake a development adapter for
    real infrastructure, so the simulated flag must be present and accurate.
    """
    adapters = (await client.get("/health")).json()["adapters"]

    assert set(adapters) >= {"cache", "jobs", "storage", "routing", "llm", "geo"}

    # The test configuration intentionally uses in-process adapters; they must say so.
    assert adapters["cache"]["backend"] == "fakeredis"
    assert adapters["cache"]["is_simulated"] is True
    assert "not a real Redis server" in adapters["cache"]["note"]

    assert adapters["jobs"]["backend"] == "inline"
    assert adapters["jobs"]["is_simulated"] is True

    # The routing adapter must state that travel times are estimated, not measured.
    assert adapters["routing"]["backend"] == "local_haversine"
    assert "ESTIMATED" in adapters["routing"]["note"]

    # Geo falls back to the documented non-PostGIS strategy (ADR-0005).
    assert adapters["geo"]["backend"] == "numeric_haversine"


async def test_ready_reports_real_postgres_and_constraints(client) -> None:
    """
    Readiness must prove the database is a supported PostgreSQL server.

    Asserting the version number, rather than merely a 200, is what makes this
    test meaningful: the schema relies on features that only exist from a known
    server version onwards.
    """
    response = await client.get("/ready")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"

    database = body["checks"]["database"]
    assert database["status"] == "ok"
    assert database["server_version"].startswith("16.")
    assert database["latency_ms"] >= 0

    # Pool metrics: in SQLAlchemy 2.x `QueuePool.size` and `.checkedout` are
    # *methods*, and returning a bound method broke JSON serialisation of this
    # payload. The key set is therefore asserted unconditionally, and the values
    # only when the pool reports metrics at all — the test session's engine uses
    # NullPool, which has none. A bound method satisfies neither branch.
    pool = database["pool"]
    assert set(pool) == {"size", "checked_out", "metrics_available"}
    if pool["metrics_available"]:
        assert isinstance(pool["size"], int)
        assert isinstance(pool["checked_out"], int)
    else:
        assert pool["size"] is None
        assert pool["checked_out"] is None


async def test_ready_warns_when_cache_is_a_development_adapter(client) -> None:
    """
    A simulated cache is usable but must be disclosed, and must not fail readiness.

    The cache is an optimisation, never a dependency (section 67), so its being
    an in-process adapter degrades nothing — but a reader has to know.
    """
    body = (await client.get("/ready")).json()

    assert body["checks"]["cache"]["backend"] == "fakeredis"
    assert body["checks"]["cache"]["is_simulated"] is True
    assert any("fakeredis" in warning for warning in body["warnings"])
    # Cache trouble never makes the instance unready.
    assert body["status"] == "ok"


async def test_metrics_exposes_application_series(client) -> None:
    """``/metrics`` serves Prometheus text exposition including our own series."""
    await client.get("/health")
    response = await client.get("/metrics")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert "ecomind_http_requests_total" in response.text
    assert "ecomind_app_info" in response.text
    # Prometheus text format requires the HELP/TYPE preamble.
    assert "# HELP ecomind_http_requests_total" in response.text
    assert "# TYPE ecomind_http_requests_total counter" in response.text


async def test_metrics_uses_route_templates_not_raw_paths(client) -> None:
    """
    Metric labels must be bounded.

    Labelling by raw path would let any client create unbounded time series by
    requesting random URLs — a memory-exhaustion vector. Unmatched requests are
    collapsed into a single ``unmatched`` series.
    """
    await client.get("/definitely-not-a-real-endpoint")
    await client.get("/another-made-up-path")
    text = (await client.get("/metrics")).text

    assert 'route="unmatched"' in text
    assert "/definitely-not-a-real-endpoint" not in text
    assert "/another-made-up-path" not in text
