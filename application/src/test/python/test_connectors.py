"""Live connectors against mocked backends (no network).

HTTP connectors get an httpx.MockTransport; ES / ClickHouse / Kubernetes get
stub clients. These check request shape, read-only probes and normalization.
"""

import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import httpx
import pytest
from incident_agent.agent.summarize import summarize
from incident_agent.connectors import ConnectorError
from incident_agent.connectors.alertmanager import Alertmanager
from incident_agent.connectors.clickhouse import ClickHouse
from incident_agent.connectors.datadog import Datadog
from incident_agent.connectors.elasticsearch import Elasticsearch
from incident_agent.connectors.kubernetes import Kubernetes
from incident_agent.connectors.prometheus import Prometheus
from kubernetes import client as k8s_models

ARGS = {"service": "checkout", "since": "00:00"}
NOW = datetime.now(timezone.utc)
TS = (NOW - timedelta(minutes=5)).timestamp()


def mock(conn, routes: dict, seen: list | None = None):
    def handler(request: httpx.Request):
        if seen is not None:
            seen.append(request)
        for (method, path), (status, body) in routes.items():
            if request.method == method and request.url.path == path:
                return httpx.Response(status, json=body)
        return httpx.Response(404, json={})
    conn.transport = httpx.MockTransport(handler)
    return conn


# ---------------------------------------------------------------- Datadog

@pytest.fixture
def dd_keys(monkeypatch):
    monkeypatch.setenv("DD_API_KEY", "k")
    monkeypatch.setenv("DD_APP_KEY", "a")
    return {"site": "datadoghq.eu", "api_key_env": "DD_API_KEY", "app_key_env": "DD_APP_KEY"}


def test_datadog_write_probe(dd_keys):
    ro = mock(Datadog(["metrics.query"], dd_keys), {("GET", "/api/v1/validate"): (200, {"valid": True}),
                                                     ("GET", "/api/v1/monitor"): (200, []),
                                                     ("POST", "/api/v1/monitor/validate"): (403, {})})
    ro.test_connection(strict=True)  # read-only key: accepted
    rw = mock(Datadog(["metrics.query"], dd_keys), {("GET", "/api/v1/validate"): (200, {"valid": True}),
                                                     ("GET", "/api/v1/monitor"): (200, []),
                                                     ("POST", "/api/v1/monitor/validate"): (200, {})})
    with pytest.raises(ConnectorError, match="not read-only"):
        rw.test_connection(strict=True)


def test_datadog_metrics_and_alerts(dd_keys):
    seen = []
    dd = mock(Datadog(["metrics.query", "alerts.list"], dd_keys), {
        ("GET", "/api/v1/query"): (200, {"series": [{"pointlist": [[TS * 1000, 58.0], [TS * 1000 + 60000, 97.0]]}]}),
        ("GET", "/api/v1/monitor"): (200, [{"name": "checkout p99", "overall_state": "Alert", "overall_state_modified": NOW.isoformat()},
                                           {"name": "ok one", "overall_state": "OK"}]),
    }, seen)
    m = dd.query("metrics.query", {**ARGS, "metric": "memory_pct"}).data
    assert [p[1] for p in m["points"]] == [58.0, 97.0]
    assert "kube_deployment:checkout" in seen[0].url.params["query"]
    assert seen[0].headers["DD-API-KEY"] == "k"
    alerts = dd.query("alerts.list", ARGS).data["alerts"]
    assert [a["name"] for a in alerts] == ["checkout p99"]


def test_datadog_logs(dd_keys):
    def handler(req):
        body = json.loads(req.content)
        if req.url.path.endswith("/events/search"):
            return httpx.Response(200, json={"data": [{"attributes": {"timestamp": NOW.isoformat()}}]})
        if "group_by" in body:
            return httpx.Response(200, json={"data": {"buckets": [{"by": {"@error.message": "OOM"}, "computes": {"c0": 388}}]}})
        return httpx.Response(200, json={"data": {"buckets": [{"by": {}, "computes": {"c0": 390}}]}})
    dd = Datadog(["logs.search"], dd_keys)
    dd.transport = httpx.MockTransport(handler)
    data = dd.query("logs.search", {**ARGS, "query": "OutOfMemory"}).data
    assert data["total"] == 390 and data["top"] == [["OOM", 388]] and data["first_seen"]


def test_missing_secret_is_a_clear_error():
    with pytest.raises(ConnectorError, match="is not set"):
        Datadog(["alerts.list"], {"api_key_env": "NOPE_NOT_SET"}).query("alerts.list", ARGS)


# ---------------------------------------------------------------- Prometheus / Alertmanager

def test_prometheus():
    seen = []
    p = mock(Prometheus(["metrics.query"], {"url": "http://prom:9090"}), {
        ("GET", "/api/v1/status/buildinfo"): (200, {}),
        ("GET", "/api/v1/status/flags"): (200, {"data": {"web.enable-admin-api": "false"}}),
        ("GET", "/api/v1/query_range"): (200, {"data": {"result": [{"values": [[TS, "11"], [TS + 60, "12"]]}]}}),
    }, seen)
    p.test_connection(strict=True)
    data = p.query("metrics.query", {**ARGS, "metric": "db_latency_ms"}).data
    assert [v for _, v in data["points"]] == [11.0, 12.0]
    assert 'service_name="checkout"' in seen[-1].url.params["query"]


def test_prometheus_with_admin_api_is_refused():
    p = mock(Prometheus(["metrics.query"], {"url": "http://prom:9090"}), {
        ("GET", "/api/v1/status/buildinfo"): (200, {}),
        ("GET", "/api/v1/status/flags"): (200, {"data": {"web.enable-admin-api": "true"}}),
    })
    with pytest.raises(ConnectorError, match="not read-only"):
        p.test_connection(strict=True)


@pytest.mark.parametrize("silence_status, accepted", [(405, True), (400, False)])
def test_alertmanager_needs_read_only_proxy(silence_status, accepted):
    am = mock(Alertmanager(["alerts.list"], {"url": "http://am:9093"}), {
        ("GET", "/api/v2/status"): (200, {}), ("POST", "/api/v2/silences"): (silence_status, {}),
        ("GET", "/api/v2/alerts"): (200, [{"labels": {"alertname": "CheckoutLatency"}, "status": {"state": "active"},
                                           "startsAt": NOW.isoformat()}]),
    })
    if accepted:
        am.test_connection(strict=True)
        assert am.query("alerts.list", ARGS).data["alerts"][0]["name"] == "CheckoutLatency"
    else:
        with pytest.raises(ConnectorError, match="not read-only"):
            am.test_connection(strict=True)


# ---------------------------------------------------------------- Elasticsearch

class StubES:
    def __init__(self, can_write=False):
        self.calls = []
        self.security = SimpleNamespace(has_privileges=lambda index: {"index": {
            "app-logs-*": {"write": can_write, "index": False, "delete": False, "manage": False}}})

    def count(self, index):
        return {"count": 1}

    def search(self, **kw):
        self.calls.append(kw)
        return {"hits": {"total": {"value": 388}},
                "aggregations": {"first_seen": {"value_as_string": NOW.isoformat()},
                                 "top": {"buckets": [{"key": "java.lang.OutOfMemoryError", "doc_count": 388}]}}}


def test_elasticsearch():
    es = Elasticsearch(["logs.search"], {"indices": ["app-logs-*"], "message_keyword_field": "message.keyword"})
    es.client = StubES()
    es.test_connection(strict=True)
    data = es.query("logs.search", {**ARGS, "query": "OutOfMemory"}).data
    assert data["total"] == 388 and data["top"][0][1] == 388
    q = es.client.calls[0]["query"]["bool"]["filter"]
    assert {"match_phrase": {"service.name": "checkout"}} in q and {"match": {"message": "OutOfMemory"}} in q
    assert "388 hits" in summarize("logs.search", data, ARGS)


def test_elasticsearch_rejects_wide_or_writable_scope():
    with pytest.raises(ConnectorError, match="not allowed"):
        Elasticsearch(["logs.search"], {"indices": ["*"]})
    with pytest.raises(ConnectorError, match="not allowed"):
        Elasticsearch(["logs.search"], {"indices": [".security"]})
    es = Elasticsearch(["logs.search"], {"indices": ["app-logs-*"]})
    es.client = StubES(can_write=True)
    with pytest.raises(ConnectorError, match="not read-only"):
        es.test_connection(strict=True)


# ---------------------------------------------------------------- ClickHouse

class StubCH:
    def __init__(self, readonly="1"):
        self.readonly, self.calls = readonly, []

    def query(self, sql, parameters=None, settings=None):
        self.calls.append((sql, parameters, settings))
        if "system.settings" in sql:
            rows = [[self.readonly]]
        elif sql.startswith("SELECT 1"):
            rows = [[1]]
        elif "count(), min(Timestamp)" in sql:
            rows = [[388, NOW]]
        elif "substring(Body" in sql:
            rows = [["java.lang.OutOfMemoryError", 388]]
        elif "count(), quantile" in sql:
            rows = [[5210, 1420.0, 214]]
        elif "GROUP BY SpanName" in sql:
            rows = [["POST /checkout", 1420.0]]
        else:
            rows = [[float("nan")]]  # db spans: none
        return SimpleNamespace(result_rows=rows)


def test_clickhouse_logs_and_traces():
    ch = ClickHouse(["logs.search", "traces.search"], {"logs_table": "otel.otel_logs"})
    ch.client = StubCH()
    ch.test_connection(strict=True)
    logs = ch.query("logs.search", {**ARGS, "query": "OutOfMemory"}).data
    assert logs["total"] == 388 and logs["top"] == [["java.lang.OutOfMemoryError", 388]]
    sql, params, settings = ch.client.calls[-2]
    assert "FROM otel.otel_logs" in sql and "{service:String}" in sql  # bound parameters, no string building
    assert params["service"] == "checkout" and params["pattern"] == "%OutOfMemory%"
    assert settings["max_execution_time"] == 10
    traces = ch.query("traces.search", ARGS).data
    assert traces["p99_ms"] == 1420.0 and traces["db_p99_ms"] is None


def test_clickhouse_refuses_writable_user_and_bad_table():
    ch = ClickHouse(["logs.search"], {})
    ch.client = StubCH(readonly="0")
    with pytest.raises(ConnectorError, match="not read-only"):
        ch.test_connection(strict=True)
    with pytest.raises(ConnectorError, match="invalid table"):
        ClickHouse(["logs.search"], {"logs_table": "otel_logs; DROP TABLE x"})


# ---------------------------------------------------------------- Kubernetes

def k8s_stub(allowed=False):
    def rs(rev, image, minutes_ago):
        return SimpleNamespace(
            metadata=SimpleNamespace(annotations={"deployment.kubernetes.io/revision": str(rev)},
                                     creation_timestamp=NOW - timedelta(minutes=minutes_ago)),
            spec=SimpleNamespace(template=SimpleNamespace(spec=SimpleNamespace(
                containers=[SimpleNamespace(image=f"registry/checkout:{image}")]))))

    def ev(name, reason, minutes_ago):
        return SimpleNamespace(involved_object=SimpleNamespace(name=name), reason=reason,
                               last_timestamp=NOW - timedelta(minutes=minutes_ago), event_time=None,
                               metadata=SimpleNamespace(creation_timestamp=None))

    return SimpleNamespace(
        models=k8s_models,
        apps=SimpleNamespace(list_namespaced_replica_set=lambda ns, label_selector: SimpleNamespace(
            items=[rs(7, "v2.8.0", 10), rs(6, "v2.7.3", 60 * 24 * 3)]),
                             list_namespaced_deployment=lambda ns, limit=None, label_selector=None, field_selector=None:
                             SimpleNamespace(items=[1] if (ns, label_selector) == ("shop", "app=checkout") else [])),
        core=SimpleNamespace(list_namespaced_event=lambda ns, limit=None: SimpleNamespace(
            items=[ev("checkout-7d9f-1", "OOMKilled", 9), ev("checkout-7d9f-2", "OOMKilled", 8), ev("payment-1", "Pulled", 5)])),
        authz=SimpleNamespace(create_self_subject_access_review=lambda body: SimpleNamespace(
            status=SimpleNamespace(allowed=allowed))),
    )


def test_kubernetes(monkeypatch):
    k = Kubernetes(["deploys.list", "k8s.events"], {"namespaces": ["checkout"]})
    k.api = k8s_stub()
    k.test_connection(strict=True)
    args = {"service": "checkout", "since": (NOW - timedelta(hours=1)).strftime("%H:%M")}
    if args["since"] > NOW.strftime("%H:%M"):  # just after midnight: skip, window maths covered elsewhere
        pytest.skip("window crosses midnight")
    deploys = k.query("deploys.list", args).data["deploys"]
    assert deploys == [{"version": "v2.8.0", "time": deploys[0]["time"], "previous": "v2.7.3"}]
    events = k.query("k8s.events", args).data
    assert events["total"] == 2 and events["reasons"] == {"OOMKilled": 2}


def _deployment(name, app):
    return SimpleNamespace(metadata=SimpleNamespace(name=name),
                           spec=SimpleNamespace(selector=SimpleNamespace(match_labels={"app": app}),
                                                template=SimpleNamespace(metadata=SimpleNamespace(labels={"app": app}),
                                                                         spec=SimpleNamespace(containers=[]))))


def test_kubernetes_finds_namespace_of_unmapped_service():
    k = Kubernetes(["deploys.list"], {"namespaces": ["other", "shop"]})
    deps = {"other": [], "shop": [_deployment("checkout-api", "checkout")]}
    k.api = SimpleNamespace(apps=SimpleNamespace(list_namespaced_deployment=lambda ns: SimpleNamespace(items=deps[ns])))
    assert k.namespace("checkout") == "shop"
    assert "-n shop " in k.native_query("deploys.list", {"service": "checkout"})
    with pytest.raises(ConnectorError, match="not in allowlist"):
        k.namespace("billing")


def test_kubernetes_matches_env_prefixed_deployment_name():
    k = Kubernetes(["deploys.list", "k8s.events"], {"namespaces": ["shop"]})
    seen = {}

    def replica_sets(ns, label_selector):
        seen["selector"] = label_selector
        return SimpleNamespace(items=[])

    k.api = SimpleNamespace(apps=SimpleNamespace(
        list_namespaced_deployment=lambda ns: SimpleNamespace(items=[_deployment("stage-cart", "stage-cart")]),
        list_namespaced_replica_set=replica_sets))
    ns, dep = k.locate("cart")
    assert (ns, dep.metadata.name) == ("shop", "stage-cart")
    assert "deployment/stage-cart" in k.native_query("deploys.list", {"service": "cart"})
    k.query("deploys.list", {"service": "cart", "since": "00:00"})
    assert seen["selector"] == "app=stage-cart"


def test_kubernetes_pods_and_logs():
    from datetime import timezone
    now = datetime.now(timezone.utc)
    term = SimpleNamespace(reason="OOMKilled", exit_code=137, finished_at=now - timedelta(minutes=3))
    crashing = SimpleNamespace(ready=False, restart_count=3,
                               state=SimpleNamespace(waiting=SimpleNamespace(reason="CrashLoopBackOff")),
                               last_state=SimpleNamespace(terminated=term))
    healthy = SimpleNamespace(ready=True, restart_count=0, state=SimpleNamespace(waiting=None),
                              last_state=SimpleNamespace(terminated=None))
    pod = lambda name, cs, app="stage-cart": SimpleNamespace(  # noqa: E731
        metadata=SimpleNamespace(name=name, labels={"app": app}), status=SimpleNamespace(phase="Running", container_statuses=[cs]),
        spec=SimpleNamespace(node_name="n1"))
    dep = _deployment("stage-cart", "stage-cart")
    dep.spec.replicas = 2
    dep.spec.template.spec.containers = [SimpleNamespace(name="cart")]
    dep.status = SimpleNamespace(ready_replicas=1, available_replicas=1, updated_replicas=2, conditions=[])
    stamp = (now - timedelta(minutes=4)).strftime("%Y-%m-%dT%H:%M:%S.123456789Z")
    logs = {("stage-cart-a", False): f"{stamp} INFO started\n{stamp} ERROR java.lang.OutOfMemoryError: Java heap space\n",
            ("stage-cart-a", True): f"{stamp} ERROR java.lang.OutOfMemoryError: Java heap space\n",
            ("stage-cart-b", False): f"{stamp} INFO ok\n"}
    k = Kubernetes(["k8s.pods", "logs.search"], {"namespaces": ["shop"]})
    k.api = SimpleNamespace(
        apps=SimpleNamespace(list_namespaced_deployment=lambda ns: SimpleNamespace(items=[dep])),
        core=SimpleNamespace(
            list_namespaced_pod=lambda ns: SimpleNamespace(items=[pod("stage-cart-b", healthy), pod("stage-cart-a", crashing),
                                                                  pod("other-x", healthy, app="other")]),
            read_namespaced_pod_log=lambda name, ns, container, timestamps, previous=False, **kw: logs[(name, previous)]))
    args = {"service": "cart", "since": (now - timedelta(minutes=30)).isoformat()}
    pods = k.query("k8s.pods", args).data
    assert (pods["total"], pods["ready"], pods["recent_restarts"]) == (2, 1, 1)
    assert pods["waiting"] == {"CrashLoopBackOff": 1} and pods["pods"][0]["pod"] == "stage-cart-a"  # unhealthy first
    assert pods["pods"][0]["last_exit"]["exit_code"] == 137
    found = k.query("logs.search", {**args, "query": "outofmemory OR timeout"}).data
    assert found["total"] == 2 and found["top"][0][1] == 1 and found["pods_read"] == 2
    assert any("[previous container]" in m for m, _ in found["top"])


def test_kubernetes_refuses_write_access_and_foreign_namespace():
    k = Kubernetes(["deploys.list"], {"namespaces": ["checkout"]})
    k.api = k8s_stub(allowed=True)
    with pytest.raises(ConnectorError, match="not read-only"):
        k.test_connection(strict=True)
    k.api = k8s_stub()
    with pytest.raises(ConnectorError, match="not in allowlist"):
        k.query("deploys.list", {"service": "billing", "since": "00:00"})


# ---------------------------------------------------------------- GKE

def test_gke_uses_cluster_endpoint_and_token(monkeypatch):
    from incident_agent.connectors.gke import GKE

    g = GKE(["deploys.list", "k8s.events"], {"project": "p", "location": "europe-west1", "cluster": "prod",
                                              "namespaces": ["checkout"]}, secrets={"service_account_json": "{}"})
    monkeypatch.setattr(g, "credentials", lambda: SimpleNamespace(token="tok"))
    import base64
    monkeypatch.setattr(g, "cluster_info", lambda token: {
        "endpoint": "34.1.2.3", "masterAuth": {"clusterCaCertificate": base64.b64encode(b"CA").decode()}})
    api = g.clients()
    cfg = api.core.api_client.configuration
    assert cfg.host == "https://34.1.2.3" and cfg.api_key["authorization"] == "Bearer tok"
    assert g.native_query("deploys.list", ARGS).startswith("[gke p/europe-west1/prod]")


def test_gke_bad_key_is_clear_error():
    from incident_agent.connectors.gke import GKE

    g = GKE(["deploys.list"], {"project": "p", "location": "l", "cluster": "c", "namespaces": ["x"]},
            secrets={"service_account_json": "not json"})
    with pytest.raises(ConnectorError, match="invalid service account key"):
        g.test_connection(strict=True)


def test_datadog_second_api_key_as_app_key_is_rejected(dd_keys):
    dd = mock(Datadog(["metrics.query"], dd_keys), {("GET", "/api/v1/validate"): (200, {"valid": True}),
                                                     ("GET", "/api/v1/monitor"): (401, {})})
    with pytest.raises(ConnectorError, match="not a second API key"):
        dd.test_connection(strict=True)


def test_writable_key_passes_with_warning_by_default(monkeypatch):
    monkeypatch.delenv("STRICT_READ_ONLY", raising=False)
    es = Elasticsearch(["logs.search"], {"indices": ["app-logs-*"]})
    es.client = StubES(can_write=True)
    warnings = es.test_connection()
    assert warnings and "can also write" in warnings[0]
    monkeypatch.setenv("STRICT_READ_ONLY", "true")
    with pytest.raises(ConnectorError, match="not read-only"):
        es.test_connection()


def test_permission_denied_still_fails(dd_keys):
    dd = mock(Datadog(["metrics.query"], dd_keys), {("GET", "/api/v1/validate"): (403, {})})
    with pytest.raises(ConnectorError, match="access denied"):
        dd.test_connection()


def test_datadog_monitor_details(dd_keys):
    dd = mock(Datadog(["alerts.list"], dd_keys), {("GET", "/api/v1/monitor/42"): (200, {
        "id": 42, "name": "High latency", "overall_state": "Alert", "type": "query alert",
        "tags": ["team:pay"], "query": "avg(last_5m):p99:trace.http.request{service:billing-api,env:prod} > 1"})})
    m = dd.monitor("42")
    assert m["service"] == "billing-api" and m["state"] == "Alert" and m["name"] == "High latency"


def test_elasticsearch_plain_text_log_field():
    """verbex style: kubernetes.container_name + plain-text `log`, no keyword copy."""
    class Stub(StubES):
        def search(self, **kw):
            self.calls.append(kw)
            return {"hits": {"total": {"value": 12}}, "aggregations": {
                "first_seen": {"value_as_string": NOW.isoformat()},
                "top": {"hits": {"hits": [{"_source": {"log": "502 Bad Gateway from webhook endpoint"}}]}}}}
    es = Elasticsearch(["logs.search"], {"indices": ["kubernetes-*"], "service_field": "kubernetes.container_name",
                                         "message_field": "log"})
    es.client = Stub()
    data = es.query("logs.search", {**ARGS, "service": "verbex-webhook-publisher", "query": "502"}).data
    call = es.client.calls[0]
    assert {"match_phrase": {"kubernetes.container_name": "verbex-webhook-publisher"}} in call["query"]["bool"]["filter"]
    assert "top_hits" in call["aggs"]["top"]
    assert data["top"] == [["502 Bad Gateway from webhook endpoint", None]]
    assert "e.g. 502 Bad Gateway" in summarize("logs.search", data, ARGS)


def test_kubernetes_pasted_kubeconfig_with_token():
    kubeconfig = """
apiVersion: v1
kind: Config
current-context: test
clusters: [{name: c1, cluster: {server: "https://10.1.2.3", insecure-skip-tls-verify: true}}]
users: [{name: u1, user: {token: abc123}}]
contexts: [{name: test, context: {cluster: c1, user: u1}}]
"""
    k = Kubernetes(["deploys.list"], {"namespaces": ["stage-app"]}, secrets={"kubeconfig": kubeconfig})
    cfg = k.clients().core.api_client.configuration
    assert cfg.host == "https://10.1.2.3" and cfg.api_key["BearerToken"] == "Bearer abc123"


def test_kubernetes_bad_kubeconfig_is_clear_error():
    k = Kubernetes(["deploys.list"], {"namespaces": ["x"]}, secrets={"kubeconfig": "not: [valid"})
    with pytest.raises(ConnectorError, match="invalid kubeconfig"):
        k.test_connection()


def test_kubernetes_bad_kubeconfig_error_does_not_quote_the_token():
    bad = "apiVersion: v1\nusers:\n- name: u\n  user:\n    token: SECRET-abc123: x: y\n"
    k = Kubernetes(["deploys.list"], {"namespaces": ["x"]}, secrets={"kubeconfig": bad})
    with pytest.raises(ConnectorError) as e:
        k.test_connection()
    assert "SECRET" not in str(e.value) and "not valid YAML at line 5" in str(e.value)
