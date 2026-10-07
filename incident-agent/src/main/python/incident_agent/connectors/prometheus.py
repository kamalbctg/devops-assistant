"""Prometheus (or Mimir/Thanos/VictoriaMetrics — same HTTP API).

settings:
    url: http://prometheus:9090
    token_env: optional bearer token env var
    service_label: label holding the service (default "service_name", OTel style)
    queries: optional overrides {generic_metric: PromQL with {label} and {s}}
"""

from datetime import timedelta

from .base import downsample
from .http import HttpConnector

DEFAULT_PROMQL = {
    "latency_p99_ms": '1000 * histogram_quantile(0.99, sum by (le) (rate(http_server_request_duration_seconds_bucket{{{label}="{s}"}}[5m])))',
    "error_rate_pct": '100 * sum(rate(http_server_request_duration_seconds_count{{{label}="{s}",http_response_status_code=~"5.."}}[5m])) / sum(rate(http_server_request_duration_seconds_count{{{label}="{s}"}}[5m]))',
    "memory_pct": '100 * max(container_memory_working_set_bytes{{container="{s}"}} / container_spec_memory_limit_bytes{{container="{s}"}})',
    "cpu_pct": '100 * sum(rate(container_cpu_usage_seconds_total{{container="{s}"}}[5m])) / sum(kube_pod_container_resource_limits{{container="{s}",resource="cpu"}})',
    "db_latency_ms": '1000 * histogram_quantile(0.99, sum by (le) (rate(db_client_operation_duration_seconds_bucket{{{label}="{s}"}}[5m])))',
}


class Prometheus(HttpConnector):
    type = "prometheus"
    supported = {"metrics.query"}
    LABEL = "Prometheus"
    FIELDS = [
        {"key": "url", "label": "URL", "type": "text", "required": True, "help": "http://prometheus:9090"},
        {"key": "service_label", "label": "Service label", "type": "text", "default": "service_name"},
        {"key": "queries", "label": "PromQL overrides (JSON)", "type": "json", "default": {}},
    ]
    DEFAULT_NOTES = """Prometheus metrics. Generic metric names are mapped to PromQL using the service
label; results are sampled time series (first, last, peak). Latency is in milliseconds, rates in
percent."""
    SECRETS = [{"key": "token", "label": "Bearer token (optional)", "required": False}]

    def promql(self, args):
        tmpl = {**DEFAULT_PROMQL, **self.settings.get("queries", {})}[args["metric"]]
        return tmpl.format(label=self.settings.get("service_label", "service_name"), s=args["service"])

    def native_query(self, capability, args):
        return f"{self.promql(args)}  [from {args['since']}]"

    def read_probe(self):
        self.get("/api/v1/status/buildinfo")

    def write_probe(self):
        """Prometheus' query API is read-only; writes need admin API or remote-write receiver."""
        flags = self.get("/api/v1/status/flags").json().get("data", {})
        return flags.get("web.enable-admin-api") == "true" or flags.get("web.enable-remote-write-receiver") == "true"

    def discover_services(self):
        label = self.settings.get("service_label", "service_name")
        return self.get(f"/api/v1/label/{label}/values").json().get("data", [])

    def fetch(self, capability, args):
        start, end = self.window(args)
        step = max(60, int((end - start) / timedelta(seconds=1) / 30))
        result = self.get("/api/v1/query_range", query=self.promql(args), start=start.timestamp(),
                          end=end.timestamp(), step=step).json()["data"]["result"]
        if not result:
            return {"points": []}
        points = [[self.hhmm(float(ts)), round(float(v), 2)] for ts, v in result[0]["values"] if v not in ("NaN", "+Inf")]
        return {"points": downsample(points)}
