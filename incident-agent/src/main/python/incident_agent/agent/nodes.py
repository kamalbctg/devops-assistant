"""Graph nodes. Each one is a plain function: (state, runtime) -> partial update.

LANGGRAPH CONCEPT — Runtime context
    `runtime.context` carries things that are NOT state: the agent config,
    the gateway and the planner. They are passed in at invoke time, are not
    saved by the checkpointer, and nodes cannot modify them through updates.
"""

import re
from dataclasses import dataclass

from langgraph.runtime import Runtime
from pydantic import ValidationError

from incident_agent.agent import analysis as post_analysis
from incident_agent.agent.alert_link import (
    parse_datadog_link,
    symptom_from,
    window_from_link,
)
from incident_agent.agent.planner import Planner
from incident_agent.agent.report import build_report, to_markdown
from incident_agent.agent.state import (
    BaselineTask,
    Conclusion,
    Evidence,
    Hypothesis,
    InvestigationState,
    Scope,
    Verdict,
)
from incident_agent.agent.summarize import crossed, metric_trend, summarize
from incident_agent.agent.tools import (
    BOARD_TOOLS,
    DATA_TOOLS,
    TOOL_TO_CAPABILITY,
    agent_tools,
)
from incident_agent.config.agent_config import AgentConfig
from incident_agent.security.gateway import Gateway

MAX_DATA_CALLS_PER_TURN = 2
KEEP_DATA = {"k8s.pods", "traces.search"}  # small structured results (no log lines) kept for the report
MAX_TRIAGE_SERVICES = 10  # services swept for alerts/metrics when the question names none
MAX_K8S_TRIAGE_SERVICES = 100  # pod health is one cached list per namespace, so sweep more
MAX_STALE_TURNS = 2  # stop after this many turns in a row that added nothing (only repeated queries)


@dataclass
class AgentContext:
    agent: AgentConfig
    gateway: Gateway
    planner: Planner


def _minus_minutes(hhmm: str, minutes: int) -> str:
    if "T" in hhmm:  # ISO timestamp
        from datetime import datetime, timedelta
        return (datetime.fromisoformat(hhmm) - timedelta(minutes=minutes)).isoformat(timespec="seconds")
    h, m = map(int, hhmm.split(":"))
    total = max(0, h * 60 + m - minutes)
    return f"{total // 60:02d}:{total % 60:02d}"


def _now_minus(tz: str, minutes: int) -> str:
    from datetime import datetime, timedelta
    from zoneinfo import ZoneInfo
    return (datetime.now(ZoneInfo(tz)) - timedelta(minutes=minutes)).strftime("%H:%M")


def _scope_from_link(question: str, ctx) -> Scope | None:
    """A pasted Datadog monitor link → service, symptom and the alert's time window."""
    link = parse_datadog_link(question)
    if not link:
        return None
    since, until = window_from_link(link)
    alert, notes = {"monitor_id": link["monitor_id"], "group": link["group"], "env": link["env"],
                    "alert_at": link["alert_at"].isoformat(timespec="seconds") if link["alert_at"] else None}, []
    dd = next((c for c in ctx.agent.connectors if c.type == "datadog"), None)
    if dd is not None:
        try:
            alert.update(dd.monitor(link["monitor_id"]))
        except Exception as e:  # monitor read failed: still use the link's time window
            notes.append(f"could not read monitor {link['monitor_id']}: {e}")
    else:
        notes.append("no Datadog connector on this agent — used only the time from the link")
    service = alert.get("service") or link["group"].get("service")
    alert["notes"] = notes
    return Scope(service=service, symptom=symptom_from(alert.get("name", "")), since=since, until=until, alert=alert)


def _is_anomalous(capability: str, data: dict, args: dict | None = None) -> bool:
    """Plain rules used to spot the affected service. Deploys are context, not anomalies."""
    if capability == "alerts.list":
        return bool(data["alerts"])
    if capability == "metrics.query":
        pts = data["points"]
        if "threshold" in data:  # the monitor's own condition
            return bool(crossed(data, args))
        return len(pts) > 1 and metric_trend(pts) in ("RISING", "SPIKE")
    if capability in ("logs.search", "k8s.events"):
        return data["total"] > 0
    if capability == "k8s.pods":
        dep = data.get("deployment") or {}
        return bool(data["ready"] < data["total"] or data["waiting"] or data["recent_restarts"]
                    or dep.get("problems") or (dep and dep["available"] < dep["desired"]))
    if capability == "traces.search":  # server errors; 4xx alone are client errors, not an incident
        return data["server_errors"] > 0 if "server_errors" in data else data["error_count"] > 0
    return False


def _when(capability: str, data: dict) -> str | None:
    if capability == "logs.search":
        return data.get("first_seen")
    if capability == "k8s.events":
        return data.get("first")
    if capability == "k8s.pods":
        return data.get("first_problem")
    if capability == "deploys.list":
        return min((d["time"] for d in data["deploys"]), default=None)
    if capability == "alerts.list":
        return min((a["since"] for a in data["alerts"] if a.get("since")), default=None)
    return None


def _run(ctx: AgentContext, evidence_id: str, capability: str, args: dict, hypothesis: str | None,
         prefix: str = "") -> Evidence:
    """Gateway call + summarize -> one evidence record. Denials become evidence too."""
    query_args = {k: v for k, v in args.items() if k != "hypothesis"}
    try:
        raw = ctx.gateway.call(capability, query_args)
        return Evidence(id=evidence_id, capability=capability, connector=raw.connector, args=query_args,
                        native_query=raw.native_query, summary=prefix + summarize(capability, raw.data, query_args),
                        hypothesis=hypothesis, anomalous=_is_anomalous(capability, raw.data, query_args),
                        when=_when(capability, raw.data), data=raw.data if capability in KEEP_DATA else None)
    except Exception as e:  # PolicyDenied, ConnectorError, source down
        return Evidence(id=evidence_id, capability=capability, connector="-", args=query_args,
                        native_query="-", summary=f"{prefix}UNAVAILABLE: {e}", hypothesis=hypothesis)


# ---------------------------------------------------------------- 1. fixed start

# The full first check: every signal, from every connector that provides it (they hold different data).
FULL_CHECK = [("alerts.list", {}), ("metrics.query", {"metric": "error_rate_pct"}),
              ("metrics.query", {"metric": "latency_p99_ms"}), ("traces.search", {}), ("logs.search", {}),
              ("deploys.list", {}), ("k8s.events", {}), ("k8s.pods", {})]


def _log_terms(scope: Scope) -> list[str]:
    """What to search the logs for, from what the alert measures (not a generic 'error')."""
    a = scope.alert or {}
    query = " ".join([a.get("query", ""), *a.get("part_queries", [])])
    text = f"{query} {a.get('name', '')} {scope.symptom}".lower()
    if "5xx" in text or "status_class:5" in text:
        excluded = set(re.findall(r"!http\.status_code:(\d{3})", query))
        return [c for c in ("500", "502", "503", "504") if c not in excluded]
    if any(w in text for w in ("latency", "slow", "p99", "duration")):
        return ["timeout", "timed out", "slow"]
    if any(w in text for w in ("oom", "memory", "restart", "crash", "down")):
        return ["OutOfMemory", "OOMKilled", "killed", "exception"]
    return ["error", "exception"]


def _log_query(terms: list[str], connector_type: str) -> str:
    # Elasticsearch `match` already means any of the words; the others take an explicit OR
    if connector_type == "elasticsearch":
        return " ".join(t for t in terms if " " not in t)
    return " OR ".join(f'"{t}"' if " " in t else t for t in terms)


def _alert_conditions(ctx: AgentContext, scope: Scope, services: list[str], win: dict) -> list[BaselineTask]:
    """The monitor's own metric (each part of a composite): exactly what triggered the alert."""
    from incident_agent.connectors.datadog import monitor_metric

    dd = next((c for c in ctx.agent.connectors if c.type == "datadog" and "metrics.query" in c.provides), None)
    tasks = []
    for cond in (scope.alert or {}).get("conditions", []):
        metric = monitor_metric(cond.get("query", ""))
        svc = cond.get("service") if ctx.agent.covers(cond.get("service")) else next(iter(services), None)
        if dd is None or metric is None or svc is None:
            continue
        tasks.append(BaselineTask(capability="metrics.query", triage=True, keep=True, args={
            "service": svc, **win, "metric": "alert_condition", "monitor_id": cond["monitor_id"],
            "monitor_query": metric["expr"], "threshold": metric["threshold"], "op": metric["op"],
            **({"connector": dd.name} if ctx.agent.connector_choices("metrics.query") else {})}))
    return tasks


def _full_check(ctx: AgentContext, scope: Scope, services: list[str], triage: bool) -> list[BaselineTask]:
    agent = ctx.agent
    caps, terms = agent.capabilities, _log_terms(scope)
    env = (scope.alert or {}).get("env")
    win = {"since": scope.since, **({"until": scope.until} if scope.until else {}), **({"env": env} if env else {})}
    tasks = _alert_conditions(ctx, scope, services, win)
    for svc in services:
        for cap, extra in FULL_CHECK:
            if cap not in caps:
                continue
            for conn in agent.connectors_for(cap):
                args = {"service": svc, **win, **extra,
                        **({"connector": conn.name} if agent.connector_choices(cap) else {}),
                        **({"query": _log_query(terms, conn.type)} if cap == "logs.search" else {})}
                tasks.append(BaselineTask(capability=cap, args=args, triage=triage, keep=True))
    return [BaselineTask(**t, id=f"B{i + 1}") for i, t in enumerate(tasks)]


def intake(state: InvestigationState, runtime: Runtime[AgentContext]) -> dict:
    ctx = runtime.context
    known = ctx.agent.known_services()
    scope = _scope_from_link(state["question"], ctx) or ctx.planner.intake(state["question"], known)
    if not scope.since:  # no start time given: look at the last hour
        scope.since = _now_minus(ctx.agent.timezone, 45)
    fresh = {"refused": None, "triage": None, "hypotheses": {}, "tool_calls_used": 0, "turns": 0,
             "notes": [], "conclusion": None, "stop_reason": None, "stale_turns": 0}

    if scope.service and not ctx.agent.covers(scope.service):
        return {**fresh, "scope": scope, "refused": f"'{scope.service}' is outside this agent's scope {ctx.agent.services}"}

    # look 15 minutes before the reported start: causes come before symptoms
    scope.since = _minus_minutes(scope.since, 15)

    if scope.service:  # one service: check everything about it
        return {**fresh, "scope": scope, "baseline_tasks": _full_check(ctx, scope, [scope.service], triage=False)}

    alert_services = [s for s in (scope.alert or {}).get("services", []) if ctx.agent.covers(s)]
    if alert_services:  # e.g. a composite monitor: check everything about each of its services
        services = alert_services[:MAX_TRIAGE_SERVICES]
        return {**fresh, "scope": scope, "baseline_tasks": _full_check(ctx, scope, services, triage=True),
                "triage": {"checked": services, "skipped": alert_services[len(services):], "alert": True}}

    # No service named and no alert: sweep the agent's services for alerts and rising
    # latency/errors (cheap signals only); the triage node picks the affected one.
    caps = ctx.agent.capabilities
    per_connector = lambda c, x: [{**x, **({"connector": n} if n else {})}  # noqa: E731
                                  for n in ctx.agent.connector_choices(c) or [None]]
    signals = [(c, y) for c, x in [("alerts.list", {}), ("k8s.pods", {}), ("metrics.query", {"metric": "latency_p99_ms"}),
                                   ("metrics.query", {"metric": "error_rate_pct"})] if c in caps for y in per_connector(c, x)]
    limit = lambda c: MAX_K8S_TRIAGE_SERVICES if c == "k8s.pods" else MAX_TRIAGE_SERVICES  # noqa: E731
    pairs = [(svc, c, x) for c, x in signals for svc in known[:limit(c)]]
    services = list(dict.fromkeys(svc for svc, _, _ in pairs))
    win = {"since": scope.since, **({"until": scope.until} if scope.until else {})}
    tasks = [BaselineTask(id=f"B{i + 1}", capability=c, args={"service": svc, **win, **x}, triage=True)
             for i, (svc, c, x) in enumerate(pairs)]
    return {**fresh, "scope": scope, "baseline_tasks": tasks,
            "triage": {"checked": services, "skipped": [s for s in known if s not in services]}}


def baseline_query(task: BaselineTask, runtime: Runtime[AgentContext]) -> dict:
    """Runs once per Send — all baseline queries run in parallel in one step."""
    prefix = f"{task['args']['service']}: " if task.get("triage") else ""
    ev = _run(runtime.context, task["id"], task["capability"], task["args"], hypothesis=None, prefix=prefix)
    if task.get("triage") and not task.get("keep") and task["capability"] == "k8s.pods" and not ev.anomalous \
            and not ev.summary.startswith(f"{prefix}UNAVAILABLE"):
        return {"evidence": []}  # a sweep of many services: keep only the unhealthy ones
    return {"evidence": [ev]}  # reducer appends; parallel runs don't overwrite each other


def _reason(e: Evidence) -> str:
    if e.capability == "alerts.list":
        return "active alerts"
    if e.capability == "k8s.pods":
        return "unhealthy pods"
    if e.capability == "metrics.query" and e.args.get("metric") == "alert_condition":
        return f"alert condition met (monitor {e.args.get('monitor_id')})"
    if e.capability == "metrics.query":
        return {"latency_p99_ms": "latency up", "error_rate_pct": "errors up"}.get(e.args.get("metric"), f"{e.args.get('metric')} up")
    if e.capability == "logs.search":
        return f"matching logs ({e.connector})"
    if e.capability == "traces.search":
        return "5xx traces"
    return e.capability


def triage(state: InvestigationState, runtime: Runtime[AgentContext]) -> dict:
    """Pick the affected service from the sweep. No-op when the question named one."""
    scope, t = state["scope"], state.get("triage")
    if scope.service or not t:
        return {}
    reasons = {svc: [] for svc in t["checked"]}
    for e in state["evidence"]:
        if e.anomalous and e.args.get("service") in reasons:
            reasons[e.args["service"]].append(_reason(e))
    ranked = sorted((s for s in reasons if reasons[s]), key=lambda s: -len(reasons[s]))
    if not ranked:
        if t.get("alert"):  # an alert happened: the model investigates all of its services
            return {"triage": {**t, "affected": None}}
        return {"triage": {**t, "affected": None}, "stop_reason": "no affected service found"}

    affected = ranked[0]
    scope = scope.model_copy(update={"service": affected})
    update = {"scope": scope, "triage": {**t, "affected": affected, "reasons": reasons[affected],
                                         "also_unusual": {s: reasons[s] for s in ranked[1:]}}}
    if t.get("alert"):  # the full check already covered deploys and events
        return update
    # deploys and events were not part of the sweep: fetch them for the affected service
    caps = runtime.context.agent.capabilities
    n = max([int(e.id[1:]) for e in state["evidence"] if e.id[1:].isdigit()] + [0])  # sweep ids can be sparse
    window = {"service": affected, "since": scope.since, **({"until": scope.until} if scope.until else {})}
    agent = runtime.context.agent
    extra = [(c, {**window, **({"connector": name} if name else {})})
             for c in ("deploys.list", "k8s.events") if c in caps for name in agent.connector_choices(c) or [None]]
    update["evidence"] = [_run(runtime.context, f"B{n + i + 1}", c, args, hypothesis=None)
                          for i, (c, args) in enumerate(extra)]
    return update


# ---------------------------------------------------------------- 2. ReAct loop

def investigate(state: InvestigationState, runtime: Runtime[AgentContext]) -> dict:
    """One ReAct turn: the planner looks at the board and picks actions; we execute them."""
    ctx = runtime.context
    budget = ctx.agent.budget
    hyps = {k: v.model_copy(deep=True) for k, v in state["hypotheses"].items()}
    evidence = list(state["evidence"])
    used = state["tool_calls_used"]
    view = {
        "question": state["question"], "scope": state["scope"], "hypotheses": hyps, "evidence": evidence,
        "notes": state["notes"], "tools": agent_tools(ctx.agent),
        "not_configured": ctx.agent.not_configured,
        "calls_left": budget.max_tool_calls - used, "turns_left": budget.max_turns - state["turns"],
        "instructions": ctx.agent.prompt,
        "alert_services": [] if state["scope"].service else (state.get("triage") or {}).get("checked", []),
        "services": ctx.agent.known_services(),
        "sources": [{"name": c.name, "type": c.type, "provides": c.provides, "notes": c.notes}
                    for c in ctx.agent.connectors if c.notes],
    }

    tool_classes = {t.__name__: t for t in view["tools"]}
    actions = ctx.planner.next_actions(view)  # THINK
    notes: list[str] = []
    new_evidence: list[Evidence] = []
    conclusion = None
    data_calls = 0
    if not actions:
        notes.append("You did not call any tool. Call a data tool or finish.")

    for action in actions:  # ACT
        name, args = action["name"], action["args"]
        try:
            if name in TOOL_TO_CAPABILITY:
                scope = state["scope"]
                if scope.since and "T" in scope.since:  # past incident: keep the model inside the alert's window
                    args = {**args, "since": scope.since}
                params = tool_classes.get(name, DATA_TOOLS[TOOL_TO_CAPABILITY[name]]).model_validate(args)  # validate first
                if data_calls >= MAX_DATA_CALLS_PER_TURN or used >= budget.max_tool_calls:
                    notes.append(f"Skipped {name}: per-turn or total budget reached.")
                    continue
                env = (scope.alert or {}).get("env")
                run_args = {**params.model_dump(), **({"until": scope.until} if scope.until else {}),
                            **({"env": env} if env else {})}
                query_args = {k: v for k, v in run_args.items() if k != "hypothesis"}  # as _run stores them
                repeat = next((e for e in evidence + new_evidence
                               if e.capability == TOOL_TO_CAPABILITY[name] and e.args == query_args), None)
                if repeat:  # give the result back, so the model uses it instead of asking again
                    notes.append(f"Skipped {name}: identical query already in evidence {repeat.id} "
                                 f"({repeat.summary[:160]}). Use it; do not ask again.")
                    continue
                used += 1
                data_calls += 1
                ev = _run(ctx, f"E{len(evidence) + len(new_evidence) + 1}", TOOL_TO_CAPABILITY[name],
                          run_args, params.hypothesis)
                new_evidence.append(ev)  # OBSERVE (summary only)
                if params.hypothesis in hyps:
                    hyps[params.hypothesis].evidence_ids.append(ev.id)

            elif name == "add_hypothesis":
                p = BOARD_TOOLS[name].model_validate(args)
                hid = f"H{len(hyps) + 1}"
                hyps[hid] = Hypothesis(id=hid, statement=p.statement)

            elif name == "set_hypothesis_status":
                p = BOARD_TOOLS[name].model_validate(args)
                if p.id not in hyps:
                    notes.append(f"Unknown hypothesis {p.id}.")
                    continue
                hyps[p.id].status = p.status
                hyps[p.id].evidence_ids = sorted(set(hyps[p.id].evidence_ids) | set(p.evidence_ids))

            elif name == "finish":
                c = Conclusion.model_validate(args)
                all_ev = {e.id: e for e in evidence + new_evidence}
                signals = {all_ev[i].capability for i in c.evidence_ids if i in all_ev}
                budget_left = used < budget.max_tool_calls and state["turns"] + 1 < budget.max_turns
                if c.kind == "answer":
                    if signals:
                        conclusion = c
                    else:
                        notes.append("finish rejected: an answer must cite at least one existing evidence id.")
                elif not c.cause_hypothesis:
                    notes.append("finish rejected: kind=root_cause needs cause_hypothesis (or use kind=answer).")
                elif len(signals) < 2 and budget_left:  # stop rule enforced in code, not trusted to the model
                    notes.append(f"finish rejected: cause needs >= 2 independent signal types, got {sorted(signals)}. "
                                 "If the question only asks for a fact, finish with kind=answer.")
                elif (c.cause_service and c.cause_service != state["scope"].service and budget_left
                      and ctx.agent.covers(c.cause_service)
                      and not any(e.args.get("service") == c.cause_service for e in all_ev.values())):
                    # blaming another service needs evidence from that service, not only from its caller
                    notes.append(f"finish rejected: the cause is in {c.cause_service}, but nothing about "
                                 f"{c.cause_service} was checked. Check it first (pods, events, deploys, logs, "
                                 "traces), then finish.")
                else:
                    conclusion = c
            else:
                notes.append(f"Unknown tool {name}.")
        except ValidationError as e:  # bad arguments go back to the model as a note
            notes.append(f"Invalid arguments for {name}: {e.errors()[0]['msg']}")

    turns = state["turns"] + 1
    # a turn that added no evidence and changed no hypothesis made no progress (e.g. only repeated queries)
    stale = 0 if (new_evidence or conclusion or hyps != state["hypotheses"]) else state.get("stale_turns", 0) + 1
    if stale == 1 and not conclusion:
        notes.append("No new evidence this turn. If further queries will not add anything, finish now with "
                     "what you have (a lower confidence is fine).")
    stop_reason = None
    if conclusion:
        stop_reason = "finished"
    elif stale >= MAX_STALE_TURNS:
        stop_reason = f"no progress: {stale} turns without new evidence"
    elif used >= budget.max_tool_calls:
        stop_reason = "budget: tool calls"
    elif turns >= budget.max_turns:
        stop_reason = "budget: turns"

    return {"hypotheses": hyps, "evidence": new_evidence, "tool_calls_used": used, "turns": turns,
            "notes": notes, "conclusion": conclusion, "stop_reason": stop_reason, "stale_turns": stale}


# ---------------------------------------------------------------- 3. fixed end

def verify(state: InvestigationState, runtime: Runtime[AgentContext]) -> dict:
    """Check the conclusion against the evidence. Plain code: deterministic and auditable."""
    agent = runtime.context.agent
    not_checked = agent.not_configured
    if state.get("refused"):
        return {"verdict": Verdict(status="out_of_scope", problems=[state["refused"]])}
    c = state.get("conclusion")
    t = state.get("triage") or {}
    if t and not t.get("affected") and state.get("stop_reason") == "no affected service found":
        return {"verdict": Verdict(status="inconclusive", not_checked=not_checked, problems=[
            f"no affected service found: checked {', '.join(t['checked'])} — no active alerts, "
            "no rising latency or errors, no unhealthy pods. Name the service to investigate it anyway."])}
    if c is None:
        return {"verdict": Verdict(status="inconclusive", not_checked=not_checked,
                                   problems=[f"stopped without a conclusion ({state.get('stop_reason')})"])}

    all_ev = {e.id: e for e in state["evidence"]}
    problems = [f"cited evidence {i} does not exist" for i in c.evidence_ids if i not in all_ev]
    usable = [all_ev[i] for i in c.evidence_ids if i in all_ev and not all_ev[i].summary.startswith(("UNAVAILABLE", "no results"))]
    signals = sorted({e.capability for e in usable})
    if c.kind == "answer":  # a fact, not a cause: no hypothesis or signal-count rules; it must rest on real data
        if not usable:
            problems.append("the answer cites no usable evidence")
        confidence = c.confidence if usable and not problems else "LOW"
        return {"verdict": Verdict(status="answered", conclusion=c, confidence=confidence,
                                   independent_signals=signals, not_checked=not_checked, problems=problems)}
    hyp = state["hypotheses"].get(c.cause_hypothesis)
    if hyp is None:
        problems.append(f"cause {c.cause_hypothesis} is not on the board")
    elif hyp.status == "ruled_out":
        problems.append(f"cause {c.cause_hypothesis} was ruled out earlier — contradiction")

    levels = ["LOW", "MEDIUM", "HIGH"]
    earned = "HIGH" if len(signals) >= 3 else "MEDIUM" if len(signals) == 2 else "LOW"
    confidence = min(earned, c.confidence, key=levels.index)
    if problems or not_checked:
        confidence = min(confidence, "MEDIUM", key=levels.index)
    if any("contradiction" in p or "not on the board" in p for p in problems):
        confidence = "LOW"
    return {"verdict": Verdict(status="root_cause_found", conclusion=c, confidence=confidence,
                               independent_signals=signals, not_checked=not_checked, problems=problems)}


def analyze(state: InvestigationState, runtime: Runtime[AgentContext]) -> dict:
    """Post-investigation analysis: the agent's own typed fields, filled by the fast model from the
    finished investigation (like post-call analysis). Never fails the run."""
    fields = runtime.context.agent.analysis_fields
    if not fields or state["verdict"].status == "out_of_scope":
        return {"analysis": None}
    ids = {e.id for e in state.get("evidence", [])}
    try:
        raw = runtime.context.planner.analyze(fields, post_analysis.transcript(state))
        return {"analysis": post_analysis.check(raw, fields, ids)}
    except Exception as e:  # model down, bad output: report it, keep the investigation
        return {"analysis": [{"name": f["name"], "type": f["type"], "value": None, "evidence_ids": [],
                              "problems": [f"analysis failed: {type(e).__name__}: {e}"]} for f in fields]}


def report(state: InvestigationState, runtime: Runtime[AgentContext]) -> dict:
    """Fixed 7-section template (agent/report.py). The model never free-writes the report."""
    data = build_report(state, runtime.context.agent)
    return {"report_data": data, "report": to_markdown(data)}
