"""Connectors: one adapter per data source type.

A connector turns a *generic* capability call (logs.search, metrics.query, ...)
into the source's native query (ES DSL, SQL, PromQL, Kubernetes API, ...)
and returns a normalized result. The agent core never sees which connector
answered — only the summarized result.
"""

from .alertmanager import Alertmanager
from .base import CAPABILITIES, Connector, ConnectorError, RawResult
from .clickhouse import ClickHouse
from .datadog import Datadog
from .elasticsearch import Elasticsearch
from .gke import GKE
from .kubernetes import Kubernetes
from .prometheus import Prometheus

CONNECTOR_TYPES: dict[str, type[Connector]] = {
    c.type: c for c in (Datadog, Elasticsearch, GKE, Kubernetes, ClickHouse, Prometheus, Alertmanager)
}

__all__ = ["CAPABILITIES", "CONNECTOR_TYPES", "Connector", "ConnectorError", "RawResult"]
