"""
Prometheus metrics.

Metrics are registered on a **private** :class:`CollectorRegistry` rather than
the library's global default. A private registry keeps test runs isolated (a
second import cannot raise ``Duplicated timeseries``) and makes ``/metrics``
exactly the set of series this application intends to publish — no accidental
Python-runtime gauges.

Label-cardinality discipline: the ``route`` label carries the *templated* path
(``/api/v1/bins/{bin_id}``), never the raw URL. Using raw paths would let a client
create unbounded series simply by requesting random URLs, which is a
memory-exhaustion vector. Unmatched requests are collapsed into ``unmatched``.
"""

from __future__ import annotations

import functools
from dataclasses import dataclass

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest

__all__ = ["Metrics", "controller_labels", "get_metrics", "reset_metrics"]

#: Latency buckets tuned for an API whose fast paths are single-digit
#: milliseconds and whose slow paths are analytics queries.
_LATENCY_BUCKETS = (
    0.005,
    0.01,
    0.025,
    0.05,
    0.1,
    0.25,
    0.5,
    1.0,
    2.5,
    5.0,
    10.0,
    30.0,
)


@dataclass(slots=True)
class Metrics:
    """The application's metric instruments and their registry."""

    registry: CollectorRegistry
    http_requests_total: Counter
    http_request_duration_seconds: Histogram
    http_requests_in_progress: Gauge
    http_request_size_bytes: Histogram
    http_response_size_bytes: Histogram
    app_info: Gauge
    dependency_up: Gauge

    def render(self) -> bytes:
        """Serialise the registry in Prometheus text exposition format."""
        return generate_latest(self.registry)


def _build() -> Metrics:
    registry = CollectorRegistry(auto_describe=True)

    return Metrics(
        registry=registry,
        http_requests_total=Counter(
            "ecomind_http_requests_total",
            "Total HTTP requests processed.",
            labelnames=("method", "route", "status"),
            registry=registry,
        ),
        http_request_duration_seconds=Histogram(
            "ecomind_http_request_duration_seconds",
            "HTTP request duration in seconds.",
            labelnames=("method", "route"),
            buckets=_LATENCY_BUCKETS,
            registry=registry,
        ),
        http_requests_in_progress=Gauge(
            "ecomind_http_requests_in_progress",
            "HTTP requests currently being processed.",
            labelnames=("method",),
            registry=registry,
        ),
        http_request_size_bytes=Histogram(
            "ecomind_http_request_size_bytes",
            "HTTP request body size in bytes as reported by Content-Length.",
            buckets=(0, 1024, 10240, 102400, 1048576, 10485760),
            registry=registry,
        ),
        http_response_size_bytes=Histogram(
            "ecomind_http_response_size_bytes",
            "HTTP response body size in bytes.",
            buckets=(0, 1024, 10240, 102400, 1048576, 10485760),
            registry=registry,
        ),
        app_info=Gauge(
            "ecomind_app_info",
            "Static application build information; the value is always 1.",
            labelnames=("version", "environment"),
            registry=registry,
        ),
        dependency_up=Gauge(
            "ecomind_dependency_up",
            "Whether a dependency is reachable (1) or not (0).",
            labelnames=("dependency",),
            registry=registry,
        ),
    )


@functools.lru_cache(maxsize=1)
def get_metrics() -> Metrics:
    """Return the process-wide metrics instance."""
    return _build()


def reset_metrics() -> None:
    """Rebuild the metrics registry. Used only by tests."""
    get_metrics.cache_clear()


def controller_labels(method: str, route: str, status_code: int) -> dict[str, str]:
    """Normalise metric labels so cardinality stays bounded."""
    status_class = f"{status_code // 100}xx"
    return {"method": method, "route": route, "status": status_class}
