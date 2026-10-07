"""Turn graph stream updates into readable lines (CLI) and JSON (API)."""

from pydantic import BaseModel


def describe(node: str, update: dict) -> str | None:
    if node == "intake":
        s = update.get("scope")
        if s is None:
            return "intake"
        text = f"scope: {s.service or 'not named — checking all services'} / {s.symptom} / from {s.since}" + (f" to {s.until}" if s.until else "")
        if s.alert:
            text += f"\nalert link: monitor {s.alert.get('monitor_id')} — {s.alert.get('name') or '?'} [{s.alert.get('state') or '?'}]"
            text += "".join(f"\nnote: {n}" for n in s.alert.get("notes", []))
        return text + (f"  REFUSED: {update['refused']}" if update.get("refused") else "")
    if node == "baseline_query":
        if not update["evidence"]:
            return None  # healthy service in a pod-health sweep: not shown
        e = update["evidence"][0]
        return f"{e.id} {e.capability} via {e.connector}: {e.summary}"
    if node == "investigate":
        lines = [f"turn {update['turns']} · calls used {update['tool_calls_used']}"]
        lines += [f"    {e.id} {e.capability} [{e.hypothesis}] via {e.connector}: {e.summary}" for e in update["evidence"]]
        lines += [f"    {h.id} [{h.status}] {h.statement}" for h in update["hypotheses"].values()]
        lines += [f"    note: {n}" for n in update["notes"]]
        if update.get("stop_reason"):
            lines.append(f"    stop: {update['stop_reason']}")
        return "\n".join(lines)
    if node == "triage":
        t = update.get("triage") or {}
        if not update:
            return "service given in the question"
        if t.get("affected"):
            return f"affected service: {t['affected']} ({', '.join(t['reasons'])}) — checked {', '.join(t['checked'])}"
        return f"no affected service found among {', '.join(t.get('checked', []))}"
    if node == "verify":
        v = update["verdict"]
        return f"{v.status} · confidence {v.confidence} · signals {v.independent_signals}"
    if node == "analyze":
        rows = update.get("analysis")
        if not rows:
            return None  # agent has no analysis fields
        return "analysis: " + " · ".join(f"{r['name']}={r['value']}" + (" ⚠" if r["problems"] else "") for r in rows)
    if node == "report":
        return "report written"
    return node


def to_jsonable(value):
    if isinstance(value, BaseModel):
        return value.model_dump()
    if isinstance(value, dict):
        return {k: to_jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_jsonable(v) for v in value]
    return value
