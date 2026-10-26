"""The investigation report: 7 fixed sections, built from verified state.

    Root Cause (or Answer) · Impact · Summary · Evidence · Recommendations ·
    Investigation Coverage · Confidence & Limitations

plus, when there is data for them: Affected Pods (from pod health), Hypotheses
(table), and Analysis — the agent's post-investigation fields, extracted by the
model and type-checked, shown apart from the verified sections.

Facts (numbers, times, coverage) come from evidence and code; the model only
supplies the cause statement, impact sentence and recommendations it passed
to `finish`, and the verifier has already checked those against evidence.
"""

CAP = {"alerts.list": "alerts", "metrics.query": "metrics", "logs.search": "logs",
       "traces.search": "traces", "deploys.list": "deploys", "k8s.events": "pod events", "k8s.pods": "pod health"}


def _monitor_excluded_codes(alert: dict | None) -> set[str]:
    """Status codes a monitor leaves out, e.g. `!http.status_code:503` -> {"503"}."""
    import re
    text = " ".join([(alert or {}).get("query", ""), *(alert or {}).get("part_queries", [])])
    return set(re.findall(r"!http\.status_code:(\d{3})", text))


def build_report(state: dict, agent) -> dict:
    v = state["verdict"]
    head = {"question": state["question"], "agent": agent.name, "status": v.status, "confidence": v.confidence}
    if v.status == "out_of_scope":
        return {**head, "refused": v.problems[0]}

    scope, c = state["scope"], v.conclusion
    evidence = state.get("evidence", [])
    hyps = list((state.get("hypotheses") or {}).values())
    t = state.get("triage") or {}
    svc_ev = [e for e in evidence if e.args.get("service") == scope.service]

    # 1. Root cause — or, for a focused question, the answer
    root = answer = None
    if c and c.kind == "answer":
        answer = {"statement": c.summary, "evidence_ids": c.evidence_ids}
    elif c:
        h = (state.get("hypotheses") or {}).get(c.cause_hypothesis)
        root = {"statement": c.summary, "hypothesis": h.statement if h else c.cause_hypothesis,
                "signals": [CAP.get(x, x) for x in v.independent_signals], "evidence_ids": c.evidence_ids}

    # 2. Impact
    impact = {
        "service": scope.service, "symptom": scope.symptom, "window_from": scope.since, "window_to": scope.until,
        "alert": scope.alert,
        "statement": c.impact if c else "",
        "alerts": [e.summary for e in svc_ev if e.capability == "alerts.list" and e.anomalous],
        "metrics": [e.summary for e in svc_ev if e.capability == "metrics.query" and e.anomalous],
        "pods": [e.summary for e in svc_ev if e.capability == "k8s.pods" and e.anomalous][-1:],
        "detected": ({"reasons": t["reasons"], "checked": t["checked"]} if t.get("affected") else None),
        "also_unusual": t.get("also_unusual") or {},
    }

    # 2b. Affected pods: the latest pod-health result for the service (structured data kept on evidence)
    pods_ev = next((e for e in reversed(svc_ev) if e.capability == "k8s.pods" and e.data), None)
    affected_pods = None
    if pods_ev:
        d = pods_ev.data
        affected_pods = {"evidence": pods_ev.id, "deployment": d.get("deployment"), "hpa": d.get("hpa"),
                         "ready": d["ready"], "total": d["total"], "pods": d["pods"]}

    # 3. Summary + timeline
    timeline = sorted(({"time": e.when, "event": f"{CAP.get(e.capability, e.capability)}: {e.summary}", "evidence": e.id}
                       for e in svc_ev if e.when and (e.anomalous or e.capability == "deploys.list")),
                      key=lambda x: x["time"])
    summary = c.summary if c else (v.problems[0] if v.problems else "No root cause found.")

    # 4. Evidence
    cited = set(c.evidence_ids) if c else set()
    ev_rows = [{"id": e.id, "capability": e.capability, "source": e.connector, "service": e.args.get("service"),
                "tests": e.hypothesis or "baseline", "finding": e.summary, "query": e.native_query,
                "cited": e.id in cited, "anomalous": e.anomalous} for e in evidence]

    # 5. Recommendations
    recs = list(c.recommendations) if c else []
    if not c:
        stop = state.get("stop_reason") or ""
        recs = ["Name the affected service and the start time, then investigate again"] if not scope.service else \
               ["Add connectors for: " + ", ".join(CAP.get(x, x) for x in v.not_checked)] if v.not_checked else \
               ["The model stopped finding new evidence. Review the evidence below; investigate again with a "
                "more specific question (service, error, time) if needed"] if stop.startswith("no progress") else \
               ["Raise the agent's tool-call or turn budget (Edit agent → Limits), then investigate again"] \
               if stop.startswith("budget") else \
               ["Widen the time window or raise the agent's tool-call budget, then investigate again"]

    # 5b. Hypotheses table
    hypotheses = [{"id": h.id, "statement": h.statement, "status": h.status, "evidence_ids": h.evidence_ids,
                   "cause": bool(c and c.cause_hypothesis == h.id)} for h in hyps]

    # 6. Coverage
    checked = sorted({(e.capability, e.connector) for e in evidence if e.connector != "-"})

    def source_of(e):  # a failed query has no connector on it: the one it asked, or the only provider
        providers = agent.connectors_for(e.capability)
        return e.args.get("connector") or (e.connector if e.connector != "-" else None) or \
            (providers[0].name if len(providers) == 1 else None)
    by_connector = []
    for conn in agent.connectors:  # every connector, also the ones that found nothing
        evs = [e for e in evidence if source_of(e) == conn.name]
        by_connector.append({"connector": conn.name, "type": conn.type, "queries": len(evs),
                             "unusual": sum(e.anomalous for e in evs), "failed": sum(e.connector == "-" for e in evs)})
    coverage = {
        "by_connector": by_connector,
        "checked": [{"capability": CAP.get(cap, cap), "source": src} for cap, src in checked],
        "not_checked": [CAP.get(x, x) for x in v.not_checked],
        "connectors_skipped": list(agent.skipped),
        "services_checked": t.get("checked") or [scope.service],
        "hypotheses": [{"id": h.id, "statement": h.statement, "status": h.status} for h in hyps],
        "effort": {"tool_calls": state.get("tool_calls_used", 0), "turns": state.get("turns", 0),
                   "queries": len(evidence), "stop": state.get("stop_reason")},
    }

    # 7. Confidence & limitations
    why = []
    if answer:
        why.append(f"answer based on {len(v.independent_signals)} signal type(s): "
                   + ", ".join(CAP.get(x, x) for x in v.independent_signals))
        why += [f"verifier notes: {p}" for p in v.problems]
    elif c:
        why.append(f"{len(v.independent_signals)} independent signal type(s) agree: {', '.join(root['signals'])}")
        ruled = [h for h in hyps if h.status == "ruled_out"]
        if ruled:
            why.append("alternatives ruled out: " + "; ".join(h.statement for h in ruled))
        why.append("verifier: every cited evidence id exists and supports the cause" if not v.problems
                   else "verifier notes: " + "; ".join(v.problems))
    limits = []
    if v.not_checked:
        limits.append("not checked (no connector): " + ", ".join(CAP.get(x, x) for x in v.not_checked) + " — confidence capped at MEDIUM")
    limits += [f"connector skipped: {s}" for s in agent.skipped]
    limits += [f"warning: {w}" for w in agent.warnings]
    if (state.get("stop_reason") or "").startswith("budget"):
        limits.append(f"stopped by budget ({state['stop_reason']}) — evidence may be incomplete")
    if t.get("skipped"):
        limits.append(f"only {len(t['checked'])} services were swept; not swept: {', '.join(t['skipped'])}")
    excluded = _monitor_excluded_codes(scope.alert)
    found_5xx = {code for e in evidence if e.capability == "traces.search" and e.data
                 for code, _, _ in e.data.get("errors_by", []) if code.startswith("5")}
    if excluded and found_5xx and found_5xx <= excluded:
        limits.append(f"all 5xx found ({', '.join(sorted(found_5xx))}) are codes the monitor ignores "
                      f"({', '.join(sorted(excluded))}): they would not trigger it — see the alert condition evidence")
    limits.append("correlation in time supports the cause but is not proof — confirm before acting")

    return {**head, "root_cause": root, "answer": answer, "impact": impact, "affected_pods": affected_pods,
            "summary": summary, "timeline": timeline, "evidence": ev_rows, "hypotheses": hypotheses,
            "recommendations": recs, "coverage": coverage, "analysis": state.get("analysis"),
            "confidence_detail": {"level": v.confidence, "why": why, "limitations": limits}}


def to_markdown(r: dict) -> str:
    out = [f"# Investigation report — {r['question']}", f"Agent: {r['agent']} · Status: {r['status'].replace('_', ' ')} · "
           f"Confidence: {r['confidence']}", ""]
    if r.get("refused"):
        return "\n".join(out + ["**Refused:** " + r["refused"]])

    rc, ans = r["root_cause"], r.get("answer")
    if ans:
        out += ["## Answer", ans["statement"], f"Evidence: {', '.join(ans['evidence_ids'])}"]
    else:
        out += ["## Root Cause"]
        out += ([rc["statement"], f"Hypothesis: {rc['hypothesis']}", f"Supported by: {', '.join(rc['signals'])} "
                 f"(evidence {', '.join(rc['evidence_ids'])})"] if rc else ["Not determined."])
    im = r["impact"]
    out += ["", "## Impact", f"Service: **{im['service'] or 'unknown'}** · symptom: {im['symptom']} · window from {im['window_from']}"]
    if im["statement"]:
        out += [im["statement"]]
    out += [f"- alert: {a}" for a in im["alerts"]] + [f"- {m}" for m in im["metrics"]]
    out += [f"- pods: {p}" for p in im.get("pods", [])]
    if im["detected"]:
        out += [f"Detected automatically ({', '.join(im['detected']['reasons'])}); checked {', '.join(im['detected']['checked'])}"]
    out += [f"Also unusual: {s} ({', '.join(x)})" for s, x in im["also_unusual"].items()]
    ap = r.get("affected_pods")
    if ap:
        out += ["", "## Affected Pods", f"{ap['ready']}/{ap['total']} ready (evidence {ap['evidence']})"]
        if ap["deployment"]:
            d = ap["deployment"]
            out += [f"Deployment {d['name']}: {d['available']}/{d['desired']} available, {d['updated']} updated"
                    + (f" · {'; '.join(d['problems'])}" if d["problems"] else "")]
        out += ["| pod | ready | restarts | state | last exit | node |", "|---|---|---|---|---|---|"]
        for p in ap["pods"]:
            e = p.get("last_exit")
            ex = f"{e['reason']} ({e['exit_code']}) at {e['at']}" if e else "—"
            out += [f"| {p['pod']} | {'yes' if p['ready'] else 'NO'} | {p['restarts']} | {p['waiting'] or p['phase']} | {ex} | {p['node'] or '—'} |"]
    out += ["", "## Summary", r["summary"]]
    if r["timeline"]:
        out += ["", "Timeline:"] + [f"- {x['time']}  {x['event']} [{x['evidence']}]" for x in r["timeline"]]
    out += ["", "## Evidence", "| id | capability | source | tests | finding |", "|---|---|---|---|---|"]
    out += [f"| {e['id']}{' *' if e['cited'] else ''} | {e['capability']} | {e['source']} | {e['tests']} | {e['finding']} |"
            for e in r["evidence"]]
    out += ["", "\\* cited for the root cause"]
    if r.get("hypotheses"):
        out += ["", "## Hypotheses", "| id | hypothesis | status | evidence |", "|---|---|---|---|"]
        out += [f"| {h['id']}{' (cause)' if h['cause'] else ''} | {h['statement']} | {h['status'].replace('_', ' ')} | "
                f"{', '.join(h['evidence_ids']) or '—'} |" for h in r["hypotheses"]]
    out += ["", "## Recommendations"] + [f"{i}. {x}" for i, x in enumerate(r["recommendations"], 1)]
    cv = r["coverage"]
    out += ["", "## Investigation Coverage",
            "Connectors: " + ("; ".join(
                f"{x['connector']}: " + (f"{x['queries']} queries, {x['unusual']} unusual"
                                         + (f", {x['failed']} failed" if x["failed"] else "") if x["queries"] else "not queried")
                for x in cv.get("by_connector", [])) or "—"),
            "Checked: " + (", ".join(f"{x['capability']} ({x['source']})" for x in cv["checked"]) or "nothing"),
            "Not checked: " + (", ".join(cv["not_checked"]) or "—"),
            "Services: " + ", ".join(s for s in cv["services_checked"] if s),
            "Hypotheses: " + ("; ".join(f"{h['id']} {h['status']}: {h['statement']}" for h in cv["hypotheses"]) or "—"),
            f"Effort: {cv['effort']['queries']} queries · {cv['effort']['tool_calls']} tool calls · "
            f"{cv['effort']['turns']} turns · stop: {cv['effort']['stop']}"]
    if cv["connectors_skipped"]:
        out += ["Connectors skipped: " + "; ".join(cv["connectors_skipped"])]
    cd = r["confidence_detail"]
    out += ["", "## Confidence & Limitations", f"Confidence: **{cd['level']}**"] + [f"- {x}" for x in cd["why"]]
    out += ["", "Limitations:"] + [f"- {x}" for x in cd["limitations"]]
    if r.get("analysis"):
        out += ["", "## Analysis (model-extracted)", "| field | value | evidence | check |", "|---|---|---|---|"]
        out += [f"| {a['name']} | {_fmt(a['value'])} | {', '.join(a['evidence_ids']) or '—'} | "
                f"{'; '.join(a['problems']) or 'ok'} |" for a in r["analysis"]]
    return "\n".join(out)


def _fmt(value) -> str:
    if value is None:
        return "—"
    if isinstance(value, list):
        return ", ".join(value) or "—"
    return str(value).replace("|", "/")
