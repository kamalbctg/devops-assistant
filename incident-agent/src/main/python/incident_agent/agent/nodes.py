"""Graph nodes. Each one is a plain function: (state, runtime) -> partial update.

LANGGRAPH CONCEPT — Runtime context
    `runtime.context` carries things that are NOT state: the agent config,
    the gateway and the planner. They are passed in at invoke time, are not
    saved by the checkpointer, and nodes cannot modify them through updates.
"""

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
from incident_agent.agent.summarize import summarize
from incident_agent.agent.tools import (
    BOARD_TOOLS,
    DATA_TOOLS,
    TOOL_TO_CAPABILITY,
    tools_for,
)
from incident_agent.config.agent_config import AgentConfig
from incident_agent.security.gateway import Gateway

MAX_DATA_CALLS_PER_TURN = 2
KEEP_DATA = {"k8s.pods"}  # structured results kept on the evidence (small, no log lines) for report tables
MAX_TRIAGE_SERVICES = 10  # services swept for alerts/metrics when the question names none
MAX_K8S_TRIAGE_SERVICES = 100  # pod health is one cached list per namespace, so sweep more


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
    alert, notes = {"monitor_id": link["monitor_id"], "group": link["group"],
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


def _is_anomalous(capability: str, data: dict) -> bool:
    """Plain rules used to spot the affected service. Deploys are context, not anomalies."""
    if capability == "alerts.list":
        return bool(data["alerts"])
    if capability == "metrics.query":
        pts = data["points"]
        return len(pts) > 1 and pts[-1][1] > pts[0][1] * 1.5 and pts[-1][1] - pts[0][1] > 1
    if capability in ("logs.search", "k8s.events"):
        return data["total"] > 0
    if capability == "k8s.pods":
        dep = data.get("deployment") or {}
        return bool(data["ready"] < data["total"] or data["waiting"] or data["recent_restarts"]
                    or dep.get("problems") or (dep and dep["available"] < dep["desired"]))
    if capability == "traces.search":
        return data["error_count"] > 0
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
                        hypothesis=hypothesis, anomalous=_is_anomalous(capability, raw.data),
                        when=_when(capability, raw.data), data=raw.data if capability in KEEP_DATA else None)
    except Exception as e:  # PolicyDenied, ConnectorError, source down
        return Evidence(id=evidence_id, capability=capability, connector="-", args=query_args,
                        native_query="-", summary=f"{prefix}UNAVAILABLE: {e}", hypothesis=hypothesis)


# ---------------------------------------------------------------- 1. fixed start

def intake(state: InvestigationState, runtime: Runtime[AgentContext]) -> dict:
    ctx = runtime.context
    known = ctx.agent.known_services()
    scope = _scope_from_link(state["question"], ctx) or ctx.planner.intake(state["question"], known)
    if not scope.since:  # no start time given: look at the last hour
        scope.since = _now_minus(ctx.agent.timezone, 45)
    fresh = {"refused": None, "triage": None, "hypotheses": {}, "tool_calls_used": 0, "turns": 0,
             "notes": [], "conclusion": None, "stop_reason": None}

    if scope.service and not ctx.agent.covers(scope.service):
        return {**fresh, "scope": scope, "refused": f"'{scope.service}' is outside this agent's scope {ctx.agent.services}"}

    # look 15 minutes before the reported start: causes come before symptoms
    scope.since = _minus_minutes(scope.since, 15)
    caps = ctx.agent.capabilities
    signals = [(c, x) for c, x in [("alerts.list", {}), ("k8s.pods", {}), ("metrics.query", {"metric": "latency_p99_ms"}),
                                   ("metrics.query", {"metric": "error_rate_pct"})] if c in caps]

    if not scope.service:
        # No service named: don't ask the user — sweep the agent's services for
        # alerts and rising latency/errors; the triage node picks the affected one.
        limit = lambda c: MAX_K8S_TRIAGE_SERVICES if c == "k8s.pods" else MAX_TRIAGE_SERVICES  # noqa: E731
        pairs = [(svc, c, x) for c, x in signals for svc in known[:limit(c)]]
        services = list(dict.fromkeys(svc for svc, _, _ in pairs))
        win = {"since": scope.since, **({"until": scope.until} if scope.until else {})}
        tasks = [BaselineTask(id=f"B{i + 1}", capability=c, args={"service": svc, **win, **x}, triage=True)
                 for i, (svc, c, x) in enumerate(pairs)]
        return {**fresh, "scope": scope, "baseline_tasks": tasks,
                "triage": {"checked": services, "skipped": [s for s in known if s not in services]}}

    base = {"service": scope.service, "since": scope.since, **({"until": scope.until} if scope.until else {})}
    wanted = signals[:1] + [(c, x) for c, x in [("deploys.list", {}), ("k8s.events", {})] if c in caps] + signals[1:]
    tasks = [BaselineTask(id=f"B{i + 1}", capability=c, args={**base, **x}) for i, (c, x) in enumerate(wanted)]
    return {**fresh, "scope": scope, "baseline_tasks": tasks}


def baseline_query(task: BaselineTask, runtime: Runtime[AgentContext]) -> dict:
    """Runs once per Send — all baseline queries run in parallel in one step."""
    prefix = f"{task['args']['service']}: " if task.get("triage") else ""
    ev = _run(runtime.context, task["id"], task["capability"], task["args"], hypothesis=None, prefix=prefix)
    if task.get("triage") and task["capability"] == "k8s.pods" and not ev.anomalous and not ev.summary.startswith(
            f"{prefix}UNAVAILABLE"):
        return {"evidence": []}  # a sweep of many services: keep only the unhealthy ones
    return {"evidence": [ev]}  # reducer appends; parallel runs don't overwrite each other


def _reason(e: Evidence) -> str:
    if e.capability == "alerts.list":
        return "active alerts"
    if e.capability == "k8s.pods":
        return "unhealthy pods"
    if e.capability == "metrics.query":
        return {"latency_p99_ms": "latency rising", "error_rate_pct": "errors rising"}.get(e.args.get("metric"), f"{e.args.get('metric')} rising")
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
        return {"triage": {**t, "affected": None}, "stop_reason": "no affected service found"}

    affected = ranked[0]
    scope = scope.model_copy(update={"service": affected})
    update = {"scope": scope, "triage": {**t, "affected": affected, "reasons": reasons[affected],
                                         "also_unusual": {s: reasons[s] for s in ranked[1:]}}}
    # deploys and events were not part of the sweep: fetch them for the affected service
    caps = runtime.context.agent.capabilities
    n = max([int(e.id[1:]) for e in state["evidence"] if e.id[1:].isdigit()] + [0])  # sweep ids can be sparse
    window = {"service": affected, "since": scope.since, **({"until": scope.until} if scope.until else {})}
    update["evidence"] = [_run(runtime.context, f"B{n + i + 1}", c, window, hypothesis=None)
                          for i, c in enumerate(c for c in ("deploys.list", "k8s.events") if c in caps)]
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
        "notes": state["notes"], "tools": tools_for(ctx.agent.capabilities),
        "not_configured": ctx.agent.not_configured,
        "calls_left": budget.max_tool_calls - used, "turns_left": budget.max_turns - state["turns"],
        "instructions": ctx.agent.prompt,
        "sources": [{"name": c.name, "type": c.type, "provides": c.provides, "notes": c.notes}
                    for c in ctx.agent.connectors if c.notes],
    }

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
                params = DATA_TOOLS[TOOL_TO_CAPABILITY[name]].model_validate(args)  # validate before running
                if data_calls >= MAX_DATA_CALLS_PER_TURN or used >= budget.max_tool_calls:
                    notes.append(f"Skipped {name}: per-turn or total budget reached.")
                    continue
                repeat = any(e.capability == TOOL_TO_CAPABILITY[name] and e.args == params.model_dump(exclude={"hypothesis"})
                             for e in evidence + new_evidence)
                if repeat:
                    notes.append(f"Skipped {name}: identical query already in evidence.")
                    continue
                used += 1
                data_calls += 1
                run_args = {**params.model_dump(), **({"until": scope.until} if scope.until else {})}
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
                else:
                    conclusion = c
            else:
                notes.append(f"Unknown tool {name}.")
        except ValidationError as e:  # bad arguments go back to the model as a note
            notes.append(f"Invalid arguments for {name}: {e.errors()[0]['msg']}")

    turns = state["turns"] + 1
    stop_reason = None
    if conclusion:
        stop_reason = "finished"
    elif used >= budget.max_tool_calls:
        stop_reason = "budget: tool calls"
    elif turns >= budget.max_turns:
        stop_reason = "budget: turns"

    return {"hypotheses": hyps, "evidence": new_evidence, "tool_calls_used": used, "turns": turns,
            "notes": notes, "conclusion": conclusion, "stop_reason": stop_reason}


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
