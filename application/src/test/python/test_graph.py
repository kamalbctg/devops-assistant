"""Run with: uv run pytest -q   (no API key needed — uses ScriptedPlanner)"""

import uuid

import pytest
from incident_agent.agent.graph import build_graph
from incident_agent.agent.nodes import AgentContext
from incident_agent.agent.planner import ScriptedPlanner
from incident_agent.config.agent_config import AgentConfig, Budget
from incident_agent.connectors import ConnectorError
from incident_agent.connectors.alertmanager import Alertmanager
from incident_agent.connectors.clickhouse import ClickHouse
from incident_agent.connectors.datadog import Datadog
from incident_agent.connectors.elasticsearch import Elasticsearch
from incident_agent.connectors.gke import GKE
from incident_agent.connectors.kubernetes import Kubernetes
from incident_agent.connectors.prometheus import Prometheus
from incident_agent.security.gateway import Gateway, PolicyDenied
from langgraph.types import Command


def make_agent(stack: str = "datadog") -> AgentConfig:
    """Two stacks, same agent: Datadog + Elasticsearch + GKE, or OTel (Alertmanager + Prometheus + ClickHouse) + K8s."""
    ns = {"namespaces": ["checkout", "payment", "cart"]}
    if stack == "datadog":
        conns = [Datadog(["alerts.list", "metrics.query", "traces.search"], {}, mode="fake"),
                 Elasticsearch(["logs.search"], {"indices": ["app-logs-*"]}, mode="fake"),
                 GKE(["deploys.list", "k8s.events"], ns, mode="fake")]
    else:
        conns = [Alertmanager(["alerts.list"], {}, mode="fake"), Prometheus(["metrics.query"], {}, mode="fake"),
                 ClickHouse(["logs.search", "traces.search"], {}, mode="fake"),
                 Kubernetes(["deploys.list", "k8s.events"], ns, mode="fake")]
    return AgentConfig(name=f"{stack}-agent", services=["checkout", "payment", "cart"], connectors=conns)


def run(question, agent, planner=None, resume=None):
    ctx = AgentContext(agent=agent, gateway=Gateway(agent), planner=planner or ScriptedPlanner())
    graph = build_graph()
    config = {"configurable": {"thread_id": str(uuid.uuid4())}}
    result = graph.invoke({"question": question}, config, context=ctx)
    if resume is not None:
        assert graph.get_state(config).interrupts, "expected the run to pause"
        result = graph.invoke(Command(resume=resume), config, context=ctx)
    return result, ctx


@pytest.mark.parametrize("stack, logs_source", [("datadog", "elasticsearch"), ("otel", "clickhouse")])
def test_same_agent_different_stacks(stack, logs_source):
    result, ctx = run("Checkout is slow since 10:04", make_agent(stack))
    v = result["verdict"]
    assert v.status == "root_cause_found"
    assert v.conclusion.cause_hypothesis == "H1"
    assert v.confidence == "HIGH"
    assert result["hypotheses"]["H2"].status == "ruled_out"
    logs = next(e for e in result["evidence"] if e.capability == "logs.search" and e.args["query"] == "OutOfMemory")
    assert logs.connector == logs_source and logs.summary.startswith("388 hits")
    assert all(a["decision"] == "allow" for a in ctx.gateway.audit)


def test_service_outside_scope_is_refused():
    result, ctx = run("Billing is slow since 10:04", make_agent())
    assert result["verdict"].status == "out_of_scope"
    assert ctx.gateway.audit == []  # nothing was queried


def test_unnamed_service_is_detected_not_asked():
    result, ctx = run("Everything is slow since 10:04", make_agent())
    t = result["triage"]
    assert t["affected"] == "checkout" and t["checked"] == ["checkout", "payment", "cart"]
    assert "active alerts" in t["reasons"] and "latency up" in t["reasons"]
    assert result["scope"].service == "checkout"
    assert result["verdict"].status == "root_cause_found"
    assert result["report_data"]["impact"]["detected"]["checked"] == ["checkout", "payment", "cart"]
    assert "Detected automatically" in result["report"]


def test_no_affected_service_found():
    agent = make_agent()
    agent.services = ["payment", "cart"]  # the demo incident is in checkout
    result, _ = run("Everything is slow since 10:04", agent)
    assert result["triage"]["affected"] is None
    assert result["verdict"].status == "inconclusive"
    assert "no affected service found" in result["verdict"].problems[0]
    assert result["tool_calls_used"] == 0  # stopped before the ReAct loop


def test_budget_stops_the_loop():
    agent = make_agent()
    agent.budget = Budget(max_tool_calls=1, max_turns=8)
    result, _ = run("Checkout is slow since 10:04", agent)
    assert result["tool_calls_used"] == 1
    # 1 data call + baseline is still >= 2 signals, so the loop may finish, but never exceeds budget
    assert result["stop_reason"] in {"budget: tool calls", "finished"}


def test_missing_connector_lowers_confidence():
    agent = make_agent()
    agent.connectors = [c for c in agent.connectors if c.type != "elasticsearch"]  # no logs
    result, _ = run("Checkout is slow since 10:04", agent)
    v = result["verdict"]
    assert "logs.search" in v.not_checked
    assert v.confidence == "MEDIUM"
    assert "Not checked: logs" in result["report"]
    assert any("not checked (no connector): logs" in x for x in result["report_data"]["confidence_detail"]["limitations"])


def test_finish_with_one_signal_is_rejected():
    class Hasty(ScriptedPlanner):
        def next_actions(self, view):
            if not view["hypotheses"]:
                return [{"name": "add_hypothesis", "args": {"statement": "bad deploy"}}]
            if not view["notes"]:
                return [{"name": "finish", "args": {"cause_hypothesis": "H1", "summary": "deploy",
                                                    "evidence_ids": ["B2"], "confidence": "HIGH"}}]
            return super().next_actions(view)

    result, _ = run("Checkout is slow since 10:04", make_agent(), planner=Hasty())
    assert result["turns"] > 2  # first finish was rejected, investigation continued
    assert result["verdict"].status == "root_cause_found"


def test_connector_with_write_access_is_refused():
    class Leaky(Elasticsearch):
        def read_probe(self):
            pass

        def write_probe(self):
            return True

    with pytest.raises(ConnectorError, match="not read-only"):
        Leaky(["logs.search"], {"indices": ["app-logs-*"]}).test_connection(strict=True)


def test_gateway_denies_unconfigured_capability_and_out_of_scope_service():
    agent = AgentConfig(name="t", services=["checkout"],
                        connectors=[Kubernetes(["deploys.list"], mode="fake")])
    gw = Gateway(agent)
    with pytest.raises(PolicyDenied):
        gw.call("logs.search", {"service": "checkout", "since": "09:00"})
    with pytest.raises(PolicyDenied):
        gw.call("deploys.list", {"service": "billing", "since": "09:00"})
    assert [a["decision"] for a in gw.audit] == ["deny", "deny"]


def two_log_sources(broken: bool = False) -> AgentConfig:
    class Broken(Datadog):
        def fetch(self, capability, args):
            raise ConnectorError("datadog logs.search failed: HTTP 400")

    dd = (Broken if broken else Datadog)(["alerts.list", "logs.search"], {"site": "x"}, mode="live" if broken else "fake",
                                         name="dd")
    es = Elasticsearch(["logs.search"], {"indices": ["logs-*"]}, mode="fake", name="es")
    return AgentConfig(name="t", services=["checkout"], connectors=[dd, es])


def test_connectors_are_equal_the_call_names_one():
    gw = Gateway(two_log_sources())
    with pytest.raises(PolicyDenied, match="choose one of"):  # no hidden priority
        gw.call("logs.search", {"service": "checkout", "since": "09:00"})
    assert gw.call("logs.search", {"service": "checkout", "since": "09:00", "connector": "es"}).connector == "es"
    assert gw.call("logs.search", {"service": "checkout", "since": "09:00", "connector": "dd"}).connector == "dd"
    with pytest.raises(PolicyDenied):
        gw.call("logs.search", {"service": "checkout", "since": "09:00", "connector": "nope"})
    # one provider: no choice needed
    assert gw.call("alerts.list", {"service": "checkout", "since": "09:00"}).connector == "dd"


def test_a_failing_connector_is_reported_not_silently_replaced():
    gw = Gateway(two_log_sources(broken=True))
    with pytest.raises(ConnectorError, match="HTTP 400"):
        gw.call("logs.search", {"service": "checkout", "since": "09:00", "connector": "dd"})
    assert gw.audit[-1]["decision"] == "deny"


def test_model_gets_a_connector_choice_only_where_several_provide():
    from typing import get_args

    from incident_agent.agent.tools import agent_tools
    tools = {t.__name__: t for t in agent_tools(two_log_sources())}
    assert get_args(tools["logs_search"].model_fields["connector"].annotation) == ("dd", "es")
    assert "connector" in tools["logs_search"].model_json_schema()["required"]
    assert "connector" not in tools["alerts_list"].model_fields
    assert tools["logs_search"].__doc__ and tools["logs_search"].__name__ == "logs_search"


def test_baseline_asks_every_connector_that_provides_a_signal():
    agent = make_agent()
    agent.connectors.append(Alertmanager(["alerts.list"], {}, mode="fake", name="am"))
    result, ctx = run("Checkout is slow since 10:04", agent)
    alerts = {e.connector for e in result["evidence"] if e.capability == "alerts.list" and e.id.startswith("B")}
    assert alerts == {"datadog", "am"}


class RepeatingPlanner(ScriptedPlanner):
    """Asks the same query every turn."""

    def next_actions(self, view):
        s = view["scope"]
        return [{"name": "logs_search", "args": {"service": s.service, "since": s.since, "hypothesis": "H1",
                                                 "query": "OutOfMemory"}}]


def test_loop_stops_when_turns_add_nothing():
    result, _ = run("Checkout is slow since 10:04", make_agent(), planner=RepeatingPlanner())
    assert result["stop_reason"] == "no progress: 2 turns without new evidence"
    assert result["turns"] == 3 and result["tool_calls_used"] == 1


def test_report_has_seven_sections_in_order():
    result, _ = run("Checkout is slow since 10:04", make_agent())
    md, r = result["report"], result["report_data"]
    sections = ["Root Cause", "Impact", "Summary", "Evidence", "Recommendations",
                "Investigation Coverage", "Confidence & Limitations"]
    positions = [md.index(f"## {s}") for s in sections]
    assert positions == sorted(positions)
    assert r["root_cause"]["signals"] and r["recommendations"]
    assert [x["time"] for x in r["timeline"]] == sorted(x["time"] for x in r["timeline"])
    assert r["timeline"][0]["event"].startswith("deploys")  # deploy 09:58 happened first
    assert any(e["cited"] for e in r["evidence"])
    assert r["coverage"]["effort"]["tool_calls"] == result["tool_calls_used"]


def _link():
    from datetime import datetime, timedelta, timezone
    at = int((datetime.now(timezone.utc) - timedelta(hours=2)).timestamp() * 1000)  # an alert 2 h ago
    return (f"https://app.datadoghq.com/monitors/264260680?group=env%3Aproduction&from_ts={at - 1200000}"
            f"&to_ts={at}&event_id=1&link_source=monitor_notif&link_monitor_id=264260680&link_event_ts={at}")


def test_link_times_in_seconds_or_milliseconds():
    from incident_agent.agent.alert_link import parse_datadog_link, window_from_link
    # a real notification link: from_ts / to_ts in ms, link_event_ts in seconds
    link = parse_datadog_link("https://app.datadoghq.com/monitors/264260680?q=env%3Aproduction&from_ts=1792768000000"
                              "&to_ts=1792769200000&link_event_ts=1792768900&link_monitor_id=264260680")
    assert link["alert_at"].isoformat() == "2026-10-23T15:21:40+00:00"
    assert link["from"].isoformat() == "2026-10-23T15:06:40+00:00"
    start, end = window_from_link(link)
    assert (start, end) == ("2026-10-23T14:51:40+00:00", "2026-10-23T15:51:40+00:00")


def test_composite_monitor_names_the_services_of_its_parts(monkeypatch):
    dd = Datadog(["alerts.list"], {"site": "datadoghq.com"}, secrets={"api_key": "k", "app_key": "a"})
    monitors = {
        "1": {"id": 1, "name": "Gateway 5xx", "type": "composite", "overall_state": "OK", "tags": ["env:prod"],
              "query": "( 2 || 3 ) && !4"},
        "2": {"type": "query alert", "tags": [], "query": "sum:trace.hits{http.status_class:5xx, service:verbex-gw} > 1"},
        "3": {"type": "query alert", "tags": [], "query": "sum:trace.hits{service:cds-gw,kube_node:x} > 1"},
        "4": {"type": "query alert", "tags": [], "query": "sum:trace.hits{!service:verbex-gw,!service:cds-gw} > 1"},
    }

    class R:
        def __init__(self, body):
            self.body = body

        def json(self):
            return self.body

    monkeypatch.setattr(dd, "get", lambda path, **kw: R(monitors[path.rsplit("/", 1)[1]]))
    m = dd.monitor("1")
    assert m["services"] == ["verbex-gw", "cds-gw"] and m["service"] is None
    assert dd.monitor("2")["service"] == "verbex-gw"


def test_composite_alert_link_triages_only_its_services():
    agent = make_agent()
    dd = next(c for c in agent.connectors if c.type == "datadog")
    dd.monitor = lambda mid: {"id": int(mid), "name": "Gateway 5xx", "state": "Alert", "service": None,
                              "services": ["payment", "cart"], "query": "( 2 || 3 ) && !4"}
    result, _ = run(_link(), agent)
    assert result["triage"]["checked"] == ["payment", "cart"]


def test_parse_datadog_link():
    from incident_agent.agent.alert_link import parse_datadog_link, window_from_link
    link = parse_datadog_link("EXPIRED" + _link())
    assert link["monitor_id"] == "264260680" and link["group"] == {"env": "production"}
    start, end = window_from_link(link)
    assert "T" in start and start < end
    assert parse_datadog_link("Checkout is slow") is None


def test_alert_link_question_uses_monitor_service_and_time():
    agent = make_agent()
    dd = next(c for c in agent.connectors if c.type == "datadog")
    dd.monitor = lambda mid: {"id": int(mid), "name": "checkout p99 latency > 800ms", "state": "Alert",
                              "service": "checkout", "query": "avg:trace.http.request{service:checkout}"}
    result, _ = run(_link(), agent)
    scope = result["scope"]
    assert scope.service == "checkout" and scope.symptom == "slow"
    assert "T" in scope.since and scope.alert["monitor_id"] == "264260680"
    assert result["verdict"].status == "root_cause_found"
    assert result["report_data"]["impact"]["alert"]["name"] == "checkout p99 latency > 800ms"


def test_monitor_read_failure_still_uses_link_time():
    agent = make_agent()
    dd = next(c for c in agent.connectors if c.type == "datadog")
    def boom(mid):
        raise RuntimeError("403")
    dd.monitor = boom
    result, _ = run(_link(), agent)
    assert "T" in result["scope"].since
    assert "could not read monitor" in result["scope"].alert["notes"][0]


def test_no_time_given_uses_last_hour_not_fixed_time():
    result, _ = run("Checkout is slow", make_agent())
    assert result["scope"].since != "09:30" and ":" in result["scope"].since


# ---------------------------------------------------------------- direct answers, pod table, analysis

class AnswerPlanner(ScriptedPlanner):
    """Answers a status question with one signal; first tries a root cause with one signal (rejected)."""

    def next_actions(self, view):
        pods = [e.id for e in view["evidence"] if e.capability == "k8s.pods"]
        if not view["notes"]:
            return [{"name": "add_hypothesis", "args": {"statement": "pods crash"}},
                    {"name": "finish", "args": {"cause_hypothesis": "H1", "summary": "crashing", "evidence_ids": pods,
                                                "confidence": "HIGH"}}]
        return [{"name": "finish", "args": {"kind": "answer", "summary": "3 of 4 checkout pods are ready; one is in "
                                            "CrashLoopBackOff after OOMKilled (137).", "evidence_ids": pods,
                                            "confidence": "HIGH"}}]


def k8s_agent(**kw):
    return AgentConfig(name="k8s", services=["checkout", "payment"],
                       connectors=[Kubernetes(["deploys.list", "k8s.events", "k8s.pods"], {"namespaces": ["checkout"]},
                                              mode="fake")], **kw)


def test_direct_answer_needs_one_signal_and_root_cause_needs_two():
    result, _ = run("What is the status of checkout pods since 10:00?", k8s_agent(), planner=AnswerPlanner())
    assert any("finish with kind=answer" in n for n in result["notes"]) or result["turns"] == 2  # first finish rejected
    v = result["verdict"]
    assert v.status == "answered" and v.conclusion.kind == "answer" and v.confidence == "HIGH"
    r = result["report_data"]
    assert r["answer"]["statement"].startswith("3 of 4") and r["root_cause"] is None
    assert "## Answer" in result["report"] and "## Root Cause" not in result["report"]


def test_affected_pods_and_hypotheses_tables():
    result, _ = run("What is the status of checkout pods since 10:00?", k8s_agent(), planner=AnswerPlanner())
    ap = result["report_data"]["affected_pods"]
    assert (ap["ready"], ap["total"]) == (3, 4)
    assert ap["pods"][0]["waiting"] == "CrashLoopBackOff" or any(p["waiting"] for p in ap["pods"])
    assert "## Affected Pods" in result["report"] and "OOMKilled (137)" in result["report"]
    assert result["report_data"]["hypotheses"][0]["statement"] == "pods crash"
    assert "## Hypotheses" in result["report"]


def test_analysis_fields_are_filled_and_type_checked():
    fields = [{"name": "failure_type", "type": "enum", "values": ["oom", "image_pull", "none"],
               "description": "kind of failure"},
              {"name": "summary_line", "type": "text", "description": "one line"},
              {"name": "rollback", "type": "boolean", "description": "rollback recommended"}]

    class Planner(ScriptedPlanner):
        def analyze(self, fields, transcript):
            assert "EVIDENCE:" in transcript and "CONCLUSION (root_cause)" in transcript
            return {"failure_type": {"value": "oom", "evidence_ids": ["B1", "X9"]},
                    "summary_line": {"value": "memory regression after v2.8.0", "evidence_ids": []},
                    "rollback": {"value": "yes"}}  # wrong type: flagged, not trusted

    agent = make_agent()
    agent.analysis_fields = fields
    result, _ = run("Checkout is slow since 10:04", agent, planner=Planner())
    rows = {a["name"]: a for a in result["analysis"]}
    assert rows["failure_type"]["value"] == "oom" and rows["failure_type"]["evidence_ids"] == ["B1"]
    assert "unknown evidence X9" in rows["failure_type"]["problems"][0]
    assert rows["rollback"]["value"] is None and "invalid boolean" in rows["rollback"]["problems"][0]
    assert "## Analysis (model-extracted)" in result["report"]


def test_analysis_failure_does_not_fail_the_run():
    class Broken(ScriptedPlanner):
        def analyze(self, fields, transcript):
            raise RuntimeError("model down")

    agent = make_agent()
    agent.analysis_fields = [{"name": "severity", "type": "text", "description": "x"}]
    result, _ = run("Checkout is slow since 10:04", agent, planner=Broken())
    assert result["verdict"].status == "root_cause_found"
    assert "analysis failed: RuntimeError: model down" in result["analysis"][0]["problems"][0]


def test_analysis_field_validation():
    from incident_agent.agent.analysis import fields_values, output_model
    ok = fields_values([{"name": "Severity", "type": "enum", "values": "SEV1, SEV2,SEV1", "description": "d"}])
    assert ok == [{"name": "severity", "type": "enum", "description": "d", "values": ["SEV1", "SEV2"]}]
    for bad in ([{"name": "1x", "description": "d"}], [{"name": "a", "type": "date", "description": "d"}],
                [{"name": "a", "description": ""}], [{"name": "a", "type": "enum", "values": ["x"], "description": "d"}],
                [{"name": "a", "description": "d"}, {"name": "a", "description": "d"}]):
        with pytest.raises(ValueError):
            fields_values(bad)
    schema = output_model(ok).model_json_schema()
    assert "severity" in schema["properties"]


# ---------------------------------------------------------------- input hardening

class RepeatPlanner(ScriptedPlanner):
    """Sends the same logs query in two turns, then finishes."""

    def next_actions(self, view):
        logs = {"name": "logs_search", "args": {"service": "checkout", "since": "10:00", "hypothesis": "H1",
                                                "query": "OutOfMemory"}}
        if not view["hypotheses"]:
            return [{"name": "add_hypothesis", "args": {"statement": "memory"}}, logs]
        if not view["notes"]:
            return [logs]
        ids = [e.id for e in view["evidence"]]
        return [{"name": "finish", "args": {"kind": "answer", "summary": "x", "evidence_ids": ids, "confidence": "LOW"}}]


def test_repeat_query_is_skipped_for_past_incident_window():
    agent = make_agent()
    next(c for c in agent.connectors if c.type == "datadog").monitor = lambda mid: {"service": "checkout"}
    result, _ = run(_link(), agent, planner=RepeatPlanner())
    assert result["scope"].until
    assert sum(e.capability == "logs.search" and e.id.startswith("E") for e in result["evidence"]) == 1
    assert result["tool_calls_used"] == 1  # the second, identical query was skipped


def test_since_is_normalized_or_rejected():
    from incident_agent.agent.state import Scope
    from incident_agent.agent.tools import logs_search
    from pydantic import ValidationError
    assert Scope(symptom="slow", since="10:04:30").since == "10:04"
    assert Scope(symptom="slow", since="at 9:05").since == "09:05"
    assert Scope(symptom="slow", since="this morning").since is None
    assert Scope(symptom="slow", since="2026-10-07T10:00:00+00:00").since.startswith("2026")
    with pytest.raises(ValidationError):
        logs_search(service="checkout", since="yesterday", hypothesis="H1")


def test_gateway_rejects_service_names_that_could_change_a_query():
    agent = make_agent()
    agent.services = []  # all services: scope alone would let any string through
    gw = Gateway(agent)
    with pytest.raises(PolicyDenied, match="invalid service name"):
        gw.call("metrics.query", {"service": 'checkout"} or up{a="', "since": "10:00", "metric": "cpu_pct"})
    assert gw.call("metrics.query", {"service": "checkout-v2.eu", "since": "10:00", "metric": "cpu_pct"})


def test_gke_ca_file_is_reused():
    pem = b"-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n"
    a, b = GKE._ca_file(pem), GKE._ca_file(pem)
    assert a == b and a.read_bytes() == pem


# ---------------------------------------------------------------- full check of an alert

def test_a_spike_that_recovered_is_unusual():
    from incident_agent.agent.summarize import metric_trend, summarize
    pts = [["14:37", 0.0], ["15:20", 57.89], ["15:51", 0.0]]
    assert metric_trend(pts) == "SPIKE"
    assert summarize("metrics.query", {"points": pts}, {"metric": "error_rate_pct"}).startswith(
        "error_rate_pct: SPIKE to 57.89 at 15:20")
    assert metric_trend([["a", 1.0], ["b", 1.2], ["c", 1.0]]) == "stable"


def test_alert_checks_every_connector_and_always_investigates():
    agent = make_agent()
    agent.connectors.append(Kubernetes(["logs.search", "k8s.pods"], {"namespaces": ["payment", "cart"]}, mode="fake",
                                       name="k8s"))
    dd = next(c for c in agent.connectors if c.type == "datadog")
    dd.monitor = lambda mid: {"id": int(mid), "name": "Gateway 5xx", "state": "OK", "service": None,
                              "services": ["payment", "cart"], "query": "( 2 || 3 ) && !4",
                              "part_queries": ["sum:trace.hits{http.status_class:5xx,!http.status_code:503,service:x}"]}
    result, _ = run(_link(), agent)
    cov = {x["connector"]: x for x in result["report_data"]["coverage"]["by_connector"]}
    assert set(cov) == {"datadog", "elasticsearch", "gke", "k8s"} and all(x["queries"] for x in cov.values())
    first = [e for e in result["evidence"] if e.id.startswith("B")]
    assert {e.args["service"] for e in first} == {"payment", "cart"}
    logs = {e.connector: e.args["query"] for e in first if e.capability == "logs.search" and e.args["service"] == "cart"}
    assert logs == {"elasticsearch": "500 502 504", "k8s": "500 OR 502 OR 504"}  # what the monitor counts, 503 excluded
    assert {e.capability for e in first} >= {"alerts.list", "metrics.query", "traces.search", "logs.search",
                                              "deploys.list", "k8s.events", "k8s.pods"}
    assert result["stop_reason"] != "no affected service found" and result["turns"] >= 1
    assert "Connectors: " in result["report"]


# ---------------------------------------------------------------- what Datadog measures, and the loop

GATEWAY_5XX = ("sum(last_2m):(default_zero(sum:trace.http.request.hits.by_http_status{http.status_class:5xx,"
               "!http.status_code:503, service:gw} by {env}.as_count())) / (default_zero(sum:trace.http.request.hits"
               "{service:gw} by {env}.as_count())) * 100 >= 1")


def test_monitor_metric_is_read_from_the_monitor_query():
    from incident_agent.connectors.datadog import monitor_metric
    m = monitor_metric(GATEWAY_5XX)
    assert m["op"] == ">=" and m["threshold"] == 1.0 and m["expr"].startswith("(default_zero(") and "last_2m" not in m["expr"]
    assert monitor_metric("( 1 || 2 ) && !3") is None


class FakeResponse:
    def __init__(self, body):
        self.body = body

    def json(self):
        return self.body


def live_datadog():
    return Datadog(["metrics.query", "traces.search", "logs.search"], {"site": "datadoghq.com"},
                   secrets={"api_key": "k", "app_key": "a"}, name="dd")


def test_datadog_error_rate_is_5xx_and_follows_the_alert_env(monkeypatch):
    dd, seen = live_datadog(), {}

    def get(path, **kw):
        seen["query"] = kw["query"]
        return FakeResponse({"series": [
            {"scope": "env:staging", "pointlist": [[1792935900000, 90.0], [1792936000000, 90.0]]},
            {"scope": "env:production", "pointlist": [[1792935900000, 0.0], [1792936000000, 2.5],
                                                      [1792936100000, 0.0]]}]})
    monkeypatch.setattr(dd, "get", get)
    r = dd.fetch("metrics.query", {"service": "gw", "since": "2026-10-25T13:45:00+00:00", "metric": "error_rate_pct",
                                   "env": "production"})
    assert "http.status_class:5xx" in seen["query"] and "trace.netty.request" in seen["query"]
    assert "service:gw,env:production" in seen["query"] and "errors" not in seen["query"]
    assert [v for _, v in r["points"]] == [0.0, 2.5, 0.0]  # the production series, not staging

    r = dd.fetch("metrics.query", {"service": "gw", "since": "2026-10-25T13:45:00+00:00", "metric": "alert_condition",
                                   "monitor_query": "sum:x{service:gw} by {env}", "threshold": 1.0, "op": ">=",
                                   "monitor_id": "7", "env": "production"})
    assert seen["query"] == "sum:x{service:gw} by {env}"
    from incident_agent.agent.summarize import summarize
    args = {"metric": "alert_condition", "op": ">=", "monitor_id": "7"}
    assert summarize("metrics.query", r, args).startswith("alert condition of monitor 7 (>= 1.0): MET 1×")
    assert dd._filter({"service": "gw", "since": "2026-10-25T13:45:00+00:00", "env": "production"},
                      "500 OR 502")["query"] == "service:gw env:production (500 OR 502)"


def test_traces_tell_4xx_from_5xx():
    from incident_agent.agent.nodes import _is_anomalous
    from incident_agent.agent.summarize import summarize
    data = {"count": 14787, "p99_ms": 3150.0, "error_count": 1914, "server_errors": 0,
            "errors_by": [["401", "GET /api/feature_flag/local_evaluation/", 1250], ["401", "POST /v1/verify", 414]],
            "slowest_ops": [["GET /v3/ai-agents", 4606.3]], "db_p99_ms": None}
    text = summarize("traces.search", data, {})
    assert "1914 errors (5xx: 0 · 1250× 401 GET /api/feature_flag" in text and "slowest (not errors)" in text
    assert not _is_anomalous("traces.search", data)  # client errors only
    assert _is_anomalous("traces.search", {**data, "server_errors": 3})


def test_elasticsearch_leaves_out_debug_lines():
    es = Elasticsearch(["logs.search"], {"indices": ["logs-*"], "message_field": "log"}, mode="fake")
    body = es.body({"service": "gw", "since": "10:00", "query": "500 502"})
    assert body["query"]["bool"]["must_not"] == [{"match_phrase": {"log": "DEBUG"}}, {"match_phrase": {"log": "TRACE"}}]
    es = Elasticsearch(["logs.search"], {"indices": ["logs-*"], "exclude_levels": []}, mode="fake")
    assert "must_not" not in es.body({"service": "gw", "since": "10:00"})["query"]["bool"]


def test_alert_link_env_and_monitor_condition_in_first_check():
    from incident_agent.agent.alert_link import parse_datadog_link
    assert parse_datadog_link(_link().replace("group=env%3Aproduction", "q=env%3Aproduction"))["env"] == "production"
    agent = make_agent()
    dd = next(c for c in agent.connectors if c.type == "datadog")
    dd.monitor = lambda mid: {"id": int(mid), "name": "Gateway 5xx", "state": "OK", "service": None,
                              "services": ["payment", "cart"], "query": "( 2 || 3 ) && !4",
                              "conditions": [{"monitor_id": "2", "query": GATEWAY_5XX, "service": "payment"}]}
    result, _ = run(_link(), agent)
    cond = [e for e in result["evidence"] if e.args.get("metric") == "alert_condition"]
    assert len(cond) == 1 and cond[0].args["monitor_id"] == "2" and cond[0].args["threshold"] == 1.0
    assert all(e.args.get("env") == "production" for e in result["evidence"] if e.id.startswith("B"))


class BlameBackendPlanner(ScriptedPlanner):
    """Finishes blaming another service; checks it only when told to."""

    def next_actions(self, view):
        s, ev = view["scope"], view["evidence"]
        if not view["hypotheses"]:
            return [{"name": "add_hypothesis", "args": {"statement": "payment backend fails"}}]
        if any("nothing about payment was checked" in n for n in view["notes"]):
            return [{"name": "k8s_events", "args": {"service": "payment", "since": s.since, "hypothesis": "H1"}}]
        ids = [next(e.id for e in ev if e.capability == c) for c in ("metrics.query", "deploys.list")]
        return [{"name": "finish", "args": {"cause_hypothesis": "H1", "cause_service": "payment", "summary": "payment",
                                            "evidence_ids": ids, "confidence": "MEDIUM"}}]


def test_blaming_another_service_needs_evidence_from_it():
    result, _ = run("Checkout is slow since 10:04", make_agent(), planner=BlameBackendPlanner())
    payment = [e for e in result["evidence"] if e.args.get("service") == "payment"]
    assert payment and result["verdict"].status == "root_cause_found"
    assert result["verdict"].conclusion.cause_service == "payment"


def test_repeated_query_gets_the_existing_result_and_a_finish_hint():
    result, _ = run("Checkout is slow since 10:04", make_agent(), planner=RepeatingPlanner())
    assert result["stop_reason"].startswith("no progress")
    assert "The model stopped finding new evidence" in result["report_data"]["recommendations"][0]


def test_downsampling_keeps_a_short_spike():
    from incident_agent.connectors.base import downsample
    pts = [[f"t{i}", 0.0] for i in range(180)]
    pts[97][1] = 9.09
    small = downsample(pts)
    assert len(small) == 12 and small[0] == pts[0] and small[-1] == pts[-1]
    assert max(v for _, v in small) == 9.09


def test_log_lines_lose_their_noise_prefixes():
    from incident_agent.agent.summarize import clean_log
    line = ("2026-10-25T14:55:48.584341355Z stdout F 2026-10-25T14:55:48.584Z  WARN [] [] [] [] --- [or-http-epoll-2] "
            "a.v.g.exception.GlobalExceptionHandler   : [503] GET /api/v1/chatflows ")
    assert clean_log(line) == "WARN --- [or-http-epoll-2] a.v.g.exception.GlobalExceptionHandler : [503] GET /api/v1/chatflows"
    assert clean_log("b'2026-10-25T13:45:27.957912979Z Loading feature flags'") == "Loading feature flags"


def test_log_lines_mask_personal_data_and_credentials():
    from incident_agent.agent.summarize import clean_log
    masked = {
        "[Client IP]: extracted client ip = 203.0.113.7 source = XFF": "[Client IP]: extracted client ip = [ip] source = XFF",
        "login failed for jane.doe+x@example.co.uk": "login failed for [email]",
        "Authorization: Bearer abcDEF123456789.xyz": "Authorization: [secret]",
        "connect failed password=hunter2secret user=app": "connect failed password=[secret] user=app",
        '{"api_key": "abc123def456"}': '{"api_key": "[secret]"}',
        "token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig rejected": "token [jwt] rejected",
        "charge 4111 1111 1111 1111 declined": "charge [number] declined",
        "sms to +8801712345678 failed": "sms to [phone] failed",
        "key AKIAIOSFODNN7EXAMPLEwJalrXUtnFEMIK7MDENG used": "key [secret] used",
    }
    for line, want in masked.items():
        assert clean_log(line) == want, line
    kept = [  # ids and names an investigation needs stay readable
        "[503] GET /api/v1/chatflows from stage-verbex-api-gateway-service-6f9c8b7d5-x2k4q",
        "trace 4bf92f3577b34da6a3ce929d0e0e4736 orgId: 1f0c2a9e-7b3d-4c11-9a52-0e6f3c1d2b4a",
        "image sha 5f0904f99153a9d3238a3e078e9e at 1792768000000 v1.0.5-SNAPSHOT",
        "see https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/503 for details",
    ]
    for line in kept:
        assert clean_log(line) == line, line


def test_traces_say_whether_5xx_came_from_downstream(monkeypatch):
    from incident_agent.agent.summarize import summarize
    dd = live_datadog()
    posts = []

    def post(path, body):
        posts.append((path, body))
        if path == "/api/v2/spans/events/search":
            return FakeResponse({"data": [{"attributes": {"trace_id": "t1"}}, {"attributes": {"trace_id": "t2"}}]})
        q = body["data"]["attributes"]["filter"]["query"]
        if q.startswith("trace_id:t1"):
            return FakeResponse({"data": [{"attributes": {"by": {"service": "cds-gw"}, "compute": {"c0": 2}}}]})
        if q.startswith("trace_id:"):
            return FakeResponse({"data": []})
        group = body["data"]["attributes"].get("group_by")
        return FakeResponse({"data": [] if group else [{"attributes": {"compute": {"c0": 3, "c1": 10}}}]})
    monkeypatch.setattr(dd, "post", post)
    args = {"service": "gw", "since": "2026-10-25T14:50:00+00:00", "until": "2026-10-25T16:20:00+00:00"}
    data = dd.fetch("traces.search", args)
    assert data["downstream_5xx"] == {"cds-gw": 2} and data["traces_checked"] == 2
    assert "-service:gw status:error" in [b["data"]["attributes"]["filter"]["query"] for _, b in posts][-1]
    assert "5xx traces call: cds-gw (2 err)" in summarize("traces.search", data, args)
    data["downstream_5xx"] = {}
    assert "5xx answered by gw itself: no downstream call in 2 sample trace(s)" in summarize("traces.search", data, args)


def test_report_says_when_found_5xx_are_codes_the_monitor_ignores():
    from incident_agent.agent.report import build_report
    from incident_agent.agent.state import Evidence, Scope, Verdict
    scope = Scope(service="gw", symptom="errors", since="10:00",
                  alert={"query": "( 2 || 3 )", "part_queries": ["sum:x{http.status_class:5xx,!http.status_code:503}"]})
    ev = Evidence(id="B1", capability="traces.search", connector="dd", args={}, native_query="-", summary="x",
                  data={"errors_by": [["503", "GET /api/v1/version", 2], ["401", "POST /v1/verify", 9]]})
    state = {"question": "q", "scope": scope, "evidence": [ev], "hypotheses": {}, "verdict": Verdict(
        status="inconclusive", confidence="LOW", independent_signals=[], not_checked=[], problems=[]), "triage": None}
    limits = build_report(state, make_agent())["confidence_detail"]["limitations"]
    assert any("are codes the monitor ignores (503)" in x for x in limits)
