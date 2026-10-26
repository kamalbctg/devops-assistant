"""Datadog: monitors, metrics, APM spans, logs — over the public HTTP API.

settings:
    site: datadoghq.com | datadoghq.eu | us5.datadoghq.com ...
    api_key_env, app_key_env: env vars holding the keys
    service_tag: tag used for the service (default "service")
    metrics: optional overrides {generic_metric: datadog metric name}
    logs_group_by: facet for top messages (default "@error.message")
Required app key scopes: metrics_read, timeseries_query, monitors_read, logs_read_data, apm_read.
"""

import re
import time

from .base import ConnectorError, downsample
from .http import HttpConnector

DEFAULT_METRICS = {
    "latency_p99_ms": "p99:trace.http.request{{{tag}:{s}}}",
    # 5xx only (4xx are client errors, rarely the incident); http and netty servers (gateways use netty)
    "error_rate_pct": "100*(default_zero(sum:trace.http.request.hits.by_http_status{{{tag}:{s},http.status_class:5xx}}.as_count())"
                      "+default_zero(sum:trace.netty.request.hits.by_http_status{{{tag}:{s},http.status_class:5xx}}.as_count()))"
                      "/(default_zero(sum:trace.http.request.hits{{{tag}:{s}}}.as_count())"
                      "+default_zero(sum:trace.netty.request.hits{{{tag}:{s}}}.as_count()))",
    "memory_pct": "100*avg:kubernetes.memory.usage{{kube_deployment:{s}}}/avg:kubernetes.memory.limits{{kube_deployment:{s}}}",
    "cpu_pct": "100*avg:kubernetes.cpu.usage.total{{kube_deployment:{s}}}/avg:kubernetes.cpu.limits{{kube_deployment:{s}}}",
    "db_latency_ms": "p99:trace.postgres.query{{{tag}:{s}}}",
}


MAX_COMPOSITE_PARTS = 10  # sub-monitors read for one composite monitor
MONITOR_QUERY = re.compile(r"^\s*\w+\(last_\w+\)\s*:\s*(?P<expr>.+?)\s*(?P<op>[<>]=?)\s*(?P<threshold>-?[\d.]+)\s*$", re.S)


def monitor_metric(query: str) -> dict | None:
    """`sum(last_2m):<metric expression> >= 1` -> {"expr", "op", "threshold"}; None for other monitor kinds."""
    m = MONITOR_QUERY.match(query or "")
    return {"expr": m["expr"], "op": m["op"], "threshold": float(m["threshold"])} if m else None

# APM names that differ from the Kubernetes container name, learned from the spans themselves
# ({(site, key): (expires_at, {container: apm_service})}); shared by the connectors of every run
_ALIASES: dict[tuple, tuple[float, dict[str, str]]] = {}
ALIAS_TTL, ALIAS_RETRY = 6 * 3600, 600

LOG_STATUS = {"error": "status:(error OR critical OR emergency OR alert)",
              "warn": "status:(warn OR error OR critical OR emergency OR alert)"}


class Datadog(HttpConnector):
    type = "datadog"
    capabilities = {"alerts.list", "metrics.query", "traces.search", "logs.search"}
    LABEL = "Datadog"
    FIELDS = [
        {"key": "site", "label": "Site", "type": "select", "default": "datadoghq.com", "required": True,
         "options": ["datadoghq.com", "datadoghq.eu", "us3.datadoghq.com", "us5.datadoghq.com", "ap1.datadoghq.com", "ddog-gov.com"]},
        {"key": "service_tag", "label": "Service tag", "type": "text", "default": "service",
         "help": "Tag that holds the service name, e.g. service:checkout"},
        {"key": "logs_group_by", "label": "Log facet for top messages", "type": "text", "default": "@error.message"},
        {"key": "metrics", "label": "Metric query overrides (JSON)", "type": "json", "default": {},
         "help": 'Optional. e.g. {"memory_pct": "100*avg:container.memory.usage{kube_deployment:{s}}/..."}'},
    ]
    DEFAULT_NOTES = """Alerts are Datadog monitors (name, state, since when). Metrics use generic names
(latency_p99_ms, error_rate_pct, memory_pct, cpu_pct, db_latency_ms) mapped to Datadog queries for
the service tag. Traces are APM spans: count, p99, error count, slowest operations. Logs (if
enabled) are Datadog logs grouped by the error facet. APM trace IDs are long hex strings and do not
match the IDs printed inside application logs."""
    SECRETS = [
        {"key": "api_key", "label": "API key", "required": True},
        {"key": "app_key", "label": "Application key", "required": False,
         "help": "Needed to read any data (40 characters). Scopes: metrics_read, timeseries_query, monitors_read, "
                 "apm_read, logs_read_data. No write scopes."},
    ]

    def base_url(self):
        return f"https://api.{self.settings.get('site', 'datadoghq.com')}"

    def headers(self):
        h = {"DD-API-KEY": self.secret("api_key")}
        app = self.secret("app_key", required=False)
        return {**h, "DD-APPLICATION-KEY": app} if app else h

    # ---- probes ----

    def read_probe(self):
        """API key valid, and the application key can read monitors (needs a real app key)."""
        self.get("/api/v1/validate")
        if not self.secret("app_key", required=False):
            raise ConnectorError("datadog: API key OK, but no Application key — Datadog needs one to read "
                                 "metrics, logs and monitors. Add it in Edit → Credentials.")
        with self.http() as c:
            r = c.get("/api/v1/monitor", params={"page_size": 1})
        if r.status_code == 401:
            raise ConnectorError("datadog: application key rejected (401) — is it an Application key, not a second API key?")
        if r.status_code == 403:
            raise ConnectorError("datadog: application key lacks monitors_read scope (403)")
        r.raise_for_status()

    def write_probe(self):
        """monitor/validate needs monitors_write but creates nothing. 403 = read-only."""
        body = {"type": "metric alert", "name": "agent-platform write probe",
                "query": "avg(last_5m):avg:system.cpu.user{*} > 100", "message": "probe"}
        with self.http() as c:
            r = c.post("/api/v1/monitor/validate", json=body)
        if r.status_code == 401:
            raise ConnectorError("datadog: invalid API/app key")
        return r.status_code != 403

    # ---- queries ----

    def _tag(self):
        return self.settings.get("service_tag", "service")

    def _filter(self, args, extra=""):
        start, end = self.window(args)
        env = f" env:{args['env']}" if args.get("env") else ""  # the alert's environment, e.g. production
        svc = f"({args['service']} OR {args['also']})" if args.get("also") else args["service"]
        q = f"{self._tag()}:{svc}{env}" + (f" ({extra})" if extra else "")  # () keeps OR inside
        return {"query": q, "from": start.isoformat(), "to": end.isoformat()}

    def _metric_query(self, args):
        if args["metric"] == "alert_condition":  # the monitor's own expression: exactly what triggered the alert
            return args["monitor_query"]
        tmpl = {**DEFAULT_METRICS, **self.settings.get("metrics", {})}[args["metric"]]
        return tmpl.format(tag=self._tag(), s=args["service"] + (f",env:{args['env']}" if args.get("env") else ""))

    def native_query(self, capability, args):
        if self.mode != "fake":
            args = self._as_apm(args)
        s = f"({args['service']} OR {args['also']})" if args.get("also") and capability != "metrics.query" else args["service"]
        if capability == "alerts.list":
            return f"GET /api/v1/monitor?monitor_tags={self._tag()}:{s}&group_states=alert,warn"
        if capability == "metrics.query":
            return f"GET /api/v1/query?query={self._metric_query(args)} from={args['since']}"
        if capability == "traces.search":
            return (f"POST /api/v2/spans/analytics/aggregate filter={self._tag()}:{s} compute=pc99(@duration),count"
                    f" group_by=resource_name from={args['since']}")
        q = " ".join(x for x in (args.get("query", ""), LOG_STATUS.get(args.get("level"), "")) if x)
        return f"POST /api/v2/logs/analytics/aggregate filter={self._tag()}:{s} {q} from={args['since']} group_by={self.settings.get('logs_group_by', '@error.message')}"

    def monitor(self, monitor_id: str) -> dict:
        """Name, state, service(s) and tags of one monitor (for alert links).
        A composite monitor names no service itself: its services are those of the sub-monitors it
        alerts on (`(A || B) && !C` -> services of A and B; C only excludes)."""
        if self.mode == "fake":
            return {}
        self.secret("app_key")
        m = self.get(f"/api/v1/monitor/{monitor_id}").json()
        if m.get("type") == "composite":
            subs = re.findall(r"(!?)\s*(\d+)", m.get("query", ""))
            services, parts = [], []
            for neg, sid in subs[:MAX_COMPOSITE_PARTS]:
                if not neg:
                    part = self.get(f"/api/v1/monitor/{sid}").json()
                    services += self._monitor_services(part)
                    parts.append({"monitor_id": sid, "query": part.get("query", ""),
                                  "service": next(iter(self._monitor_services(part)), None)})
        else:
            services = self._monitor_services(m)
            parts = [{"monitor_id": str(m.get("id")), "query": m.get("query", ""), "service": next(iter(services), None)}]
        services = list(dict.fromkeys(services))
        return {"id": m.get("id"), "name": m.get("name", ""), "state": m.get("overall_state"),
                "service": services[0] if len(services) == 1 else None, "services": services,
                "tags": m.get("tags", []), "query": m.get("query", ""), "type": m.get("type"),
                "part_queries": [p["query"] for p in parts], "conditions": parts}

    def _monitor_services(self, m: dict) -> list[str]:
        """The service tag, else every `service:x` filter in the query (not `!service:x`, which excludes)."""
        tag = self._tag()
        tags = dict(t.split(":", 1) for t in m.get("tags", []) if ":" in t)
        found = [tags[tag]] if tags.get(tag) else \
            re.findall(rf"(?<![!\w.-]){re.escape(tag)}:([A-Za-z0-9_.\-]+)", m.get("query", ""))
        return [self.common_name(x) for x in found]

    def discover_services(self):
        self.secret("app_key")
        names = set()
        tag = self._tag()
        r = self.post("/api/v2/logs/analytics/aggregate", {
            "compute": [{"aggregation": "count"}], "filter": {"query": "*", "from": "now-24h", "to": "now"},
            "group_by": [{"facet": tag, "limit": 200, "sort": {"type": "measure", "aggregation": "count", "order": "desc"}}]}).json()
        names |= {str(b["by"].get(tag)) for b in r.get("data", {}).get("buckets", []) if b["by"].get(tag)}
        now = int(time.time())  # v1 query takes epoch seconds, not "now-24h"
        series = self.get("/api/v1/query", query=f"sum:trace.http.request.hits{{*}} by {{{tag}}}.as_count()",
                          **{"from": now - 86400, "to": now}).json().get("series", [])
        names |= {sc.split(":", 1)[1] for s in series for sc in s.get("scope", "").split(",") if sc.startswith(tag + ":")}
        return list({self.common_name(n) for n in names if n not in ("N/A", "None")})

    # ---- service names: one name everywhere, the APM name only on the way to Datadog ----

    def aliases(self) -> dict[str, str]:
        """{container name: APM service name} where they differ, e.g. agent-call-cmd-service -> call-cmd-service.

        Read from 24 h of server spans (client spans such as mongo or redis are left out), cached for a few
        hours. A container whose own name is also an APM service needs no alias. Never fails a query."""
        if self.mode == "fake":
            return {}
        key = (self.settings.get("site"), self.secret("api_key"))
        hit = _ALIASES.get(key)
        if hit and hit[0] > time.time():
            return hit[1]
        try:
            self.secret("app_key")
            count = {"aggregation": "count", "order": "desc", "type": "measure"}
            r = self.post("/api/v2/spans/analytics/aggregate", {"data": {"type": "aggregate_request", "attributes": {
                "compute": [{"aggregation": "count"}],
                "filter": {"query": "-@span.kind:client", "from": "now-24h", "to": "now"},
                # Datadog allows at most 10 000 groups in all: 500 services x 5 containers each
                "group_by": [{"facet": "service", "limit": 500, "sort": count},
                             {"facet": "kube_container_name", "limit": 5, "sort": count}]}}})
            rows = [b.get("attributes", {}) for b in r.json().get("data", [])]
            pairs = [(str(r["by"].get("service")), str(r["by"].get("kube_container_name")), int(r["compute"]["c0"]))
                     for r in rows if r.get("by", {}).get("service") and r["by"].get("kube_container_name")]
        except Exception:  # noqa: BLE001 — without aliases queries still run under the name given
            _ALIASES[key] = (time.time() + ALIAS_RETRY, {})
            return {}
        services = {svc for svc, _, _ in pairs}
        best: dict[str, tuple[str, int]] = {}
        for svc, container, n in pairs:
            if container not in services and svc != container and n > best.get(container, ("", -1))[1]:
                best[container] = (svc, n)
        found = {c: svc for c, (svc, _) in best.items()}
        _ALIASES[key] = (time.time() + ALIAS_TTL, found)
        return found

    def apm_name(self, service: str) -> str:
        return self.aliases().get(service, service)

    def common_name(self, apm_service: str) -> str:
        """The other way: an APM name (from a monitor or a trace) as the name the other sources use."""
        back = {}
        for container, svc in self.aliases().items():
            back.setdefault(svc, []).append(container)
        return back[apm_service][0] if len(back.get(apm_service, [])) == 1 else apm_service

    def _as_apm(self, args: dict) -> dict:
        """args with the APM name; the original kept so logs (tagged with the container name) match either."""
        apm = self.apm_name(args["service"])
        return {**args, "service": apm, **({"also": args["service"]} if apm != args["service"] else {})}

    def fetch(self, capability, args):
        self.secret("app_key")  # every read endpoint needs it
        args = self._as_apm(args)
        return {"alerts.list": self._alerts, "metrics.query": self._metrics,
                "traces.search": self._traces, "logs.search": self._logs}[capability](args)

    def _alerts(self, args):
        monitors = {}  # monitors may be tagged with either name
        for name in filter(None, (args["service"], args.get("also"))):
            for m in self.get("/api/v1/monitor", monitor_tags=f"{self._tag()}:{name}", group_states="alert,warn").json():
                monitors.setdefault(m.get("id"), m)
        monitors = list(monitors.values())
        return {"alerts": [{"name": m["name"], "status": m.get("overall_state", "?"),
                            "since": self.hhmm(m.get("overall_state_modified")) or "?"}
                           for m in monitors if m.get("overall_state") in ("Alert", "Warn", "No Data")]}

    def _metrics(self, args):
        start, end = self.window(args)
        series = self.get("/api/v1/query", query=self._metric_query(args),
                          **{"from": int(start.timestamp()), "to": int(end.timestamp())}).json().get("series", [])
        if args.get("env"):  # a query grouped `by {env}` returns one series per environment
            series = [s for s in series if f"env:{args['env']}" in s.get("scope", "").split(",")] or series
        if not series:
            return {"points": []}
        points = [[self.hhmm(ts / 1000), round(v, 2)] for ts, v in series[0]["pointlist"] if v is not None]
        return {"points": downsample(points), **({"threshold": args["threshold"]} if "threshold" in args else {})}

    def _logs(self, args):
        f = self._filter(args, args.get("query", ""))
        if args.get("level"):
            f["query"] += " " + LOG_STATUS[args["level"]]
        count = self.post("/api/v2/logs/analytics/aggregate",
                          {"compute": [{"aggregation": "count"}], "filter": f}).json()
        buckets = count.get("data", {}).get("buckets", [])
        total = int(buckets[0]["computes"]["c0"]) if buckets else 0
        facet = self.settings.get("logs_group_by", "@error.message")
        top = self.post("/api/v2/logs/analytics/aggregate", {
            "compute": [{"aggregation": "count"}], "filter": f,
            "group_by": [{"facet": facet, "limit": 3, "sort": {"type": "measure", "aggregation": "count", "order": "desc"}}],
        }).json().get("data", {}).get("buckets", [])
        first = self.post("/api/v2/logs/events/search", {"filter": f, "sort": "timestamp", "page": {"limit": 1}}).json()
        first_ts = (first.get("data") or [{}])[0].get("attributes", {}).get("timestamp")
        return {"total": total, "first_seen": self.hhmm(first_ts, seconds=True),
                "top": [[str(b["by"].get(facet)), int(b["computes"]["c0"])] for b in top]}

    def _spans(self, f, group_by=None, compute=None, limit=3, sort=None):
        attrs = {"compute": compute or [{"aggregation": "pc99", "metric": "@duration"}, {"aggregation": "count"}], "filter": f}
        if group_by:
            sort = sort or {"aggregation": "pc99", "metric": "@duration", "order": "desc", "type": "measure"}
            attrs["group_by"] = [{"facet": g, "limit": limit, "sort": sort}
                                 for g in ([group_by] if isinstance(group_by, str) else group_by)]
        r = self.post("/api/v2/spans/analytics/aggregate", {"data": {"type": "aggregate_request", "attributes": attrs}})
        return [b.get("attributes", {}) for b in r.json().get("data", [])]

    def _traces(self, args):
        ms = lambda ns: round(ns / 1e6, 1) if ns is not None else None  # noqa: E731 — Datadog durations are ns
        overall = (self._spans(self._filter(args)) or [{}])[0].get("compute", {})
        count = [{"aggregation": "count"}]
        errors = (self._spans(self._filter(args, "status:error"), compute=count) or [{}])[0].get("compute", {})
        # what the errors are: status code + route, so 4xx (client) and 5xx (server) are told apart
        by_code = self._spans(self._filter(args, "status:error"), group_by=["@http.status_code", "resource_name"],
                              compute=count, limit=6, sort={"aggregation": "count", "order": "desc", "type": "measure"})
        e5 = (self._spans(self._filter(args, "@http.status_code:>=500"), compute=count) or [{}])[0].get("compute", {})
        ops = self._spans(self._filter(args), group_by="resource_name")
        db = (self._spans(self._filter(args, "@db.system:*")) or [{}])[0].get("compute", {})
        down = self._downstream_of_5xx(args) if int(e5.get("c0", 0) or 0) else {}
        return {"count": int(overall.get("c1", 0) or 0), "p99_ms": ms(overall.get("c0")),
                "error_count": int(errors.get("c0", 0) or 0), "server_errors": int(e5.get("c0", 0) or 0),
                "errors_by": [[str(b["by"].get("@http.status_code")), b["by"].get("resource_name"), int(b["compute"]["c0"])]
                              for b in by_code],
                "slowest_ops": [[o["by"]["resource_name"], ms(o["compute"]["c0"])] for o in ops],
                "db_p99_ms": ms(db.get("c0")), **down}

    def _downstream_of_5xx(self, args, samples: int = 3) -> dict:
        """Did the 5xx come from a call to another service, or did the service answer 5xx itself?
        Reads a few 5xx traces and lists the other services in them (with their error spans)."""
        f = self._filter(args, "@http.status_code:>=500")
        try:
            found = self.post("/api/v2/spans/events/search", {"data": {"type": "search_request", "attributes": {
                "filter": f, "sort": "-timestamp", "page": {"limit": samples}}}}).json().get("data", [])
            traces = list(dict.fromkeys(s.get("attributes", {}).get("trace_id") for s in found))[:samples]
            down: dict[str, int] = {}
            for tid in filter(None, traces):
                me = f"({args['service']} OR {args['also']})" if args.get("also") else args["service"]
                spans = self._spans({"query": f"trace_id:{tid} -{self._tag()}:{me} status:error",
                                     "from": f["from"], "to": f["to"]},
                                    group_by=f"{self._tag()}", compute=[{"aggregation": "count"}], limit=5,
                                    sort={"aggregation": "count", "order": "desc", "type": "measure"})
                for b in spans:
                    name = self.common_name(str(b["by"].get(self._tag())))
                    down[name] = down.get(name, 0) + int(b["compute"]["c0"])
            return {"downstream_5xx": down, "traces_checked": len([t for t in traces if t])}
        except ConnectorError:
            return {}

