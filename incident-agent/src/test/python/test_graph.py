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
    logs = next(e for e in result["evidence"] if e.capability == "logs.search")
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
    assert "active alerts" in t["reasons"] and "latency rising" in t["reasons"]
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


def test_gateway_falls_back_to_next_connector_when_first_fails():
    class Broken(Datadog):
        def fetch(self, capability, args):
            raise ConnectorError("datadog logs.search failed: HTTP 400")

    agent = AgentConfig(name="t", services=["checkout"],
                        connectors=[Broken(["logs.search"], {"site": "x"}), Elasticsearch(["logs.search"], {"indices": ["logs-*"]}, mode="fake")])
    gw = Gateway(agent)
    result = gw.call("logs.search", {"service": "checkout", "since": "09:00"})
    assert result.connector == "elasticsearch"
    assert gw.audit[-1]["decision"] == "allow" and "HTTP 400" in gw.audit[-1]["fallback_from"][0]


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
