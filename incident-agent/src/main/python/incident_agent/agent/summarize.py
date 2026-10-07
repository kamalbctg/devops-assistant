"""Summarizer: normalized connector result -> one line the model can read.

Raw log lines never reach the model (cost, prompt injection, secrets). This
version is plain code; swap in a fast model (Haiku) when results get fuzzy.
"""


def _clip(s: str, n: int = 70) -> str:
    s = " ".join(str(s).split())
    return s if len(s) <= n else s[: n - 1] + "…"


def _pods(data: dict) -> str:
    dep = data.get("deployment")
    if not data["total"]:
        return f"no pods found (deployment wants {dep['desired']})" if dep else "no pods found"
    parts = [f"{data['ready']}/{data['total']} pods ready"]
    if dep:
        parts.append(f"deployment {dep['name']} {dep['available']}/{dep['desired']} available, {dep['updated']} updated")
    parts.append(f"{data['restarts']} restarts total, {data['recent_restarts']} pods restarted in window")
    if data["waiting"]:
        parts.append("waiting: " + ", ".join(f"{n}× {r}" for r, n in data["waiting"].items()))
    exits = [p for p in data["pods"] if p.get("last_exit")]
    if exits:
        p = max(exits, key=lambda p: (p["last_exit"]["recent"], p["last_exit"]["at"] or ""))
        e = p["last_exit"]
        parts.append(f"last exit: {e['reason']} (code {e['exit_code']}) at {e['at']} on {p['pod']}")
    if dep and dep["problems"]:
        parts.append("conditions: " + "; ".join(dep["problems"]))
    if data.get("hpa"):
        h = data["hpa"]
        parts.append(f"HPA {h['current']}→{h['desired']} (min {h['min']}, max {h['max']})"
                     + (" AT MAX" if h["current"] and h["current"] >= h["max"] else ""))
    return " · ".join(parts)


def summarize(capability: str, data: dict, args: dict) -> str:
    if capability == "logs.search":
        if not data["total"]:
            return "0 hits"
        if data["top"] and data["top"][0][1] is None:  # example lines (plain-text message field)
            return f"{data['total']} hits · first seen {data['first_seen']} · e.g. " + " | ".join(_clip(m, 90) for m, _ in data["top"])
        tops = "; ".join(f"{n}× {_clip(m)}" for m, n in data["top"])
        return f"{data['total']} hits · first seen {data['first_seen']} · top: {tops or '-'}"

    if capability == "metrics.query":
        pts = data["points"]
        if not pts:
            return f"{args['metric']}: no data"
        (t0, v0), (t1, v1) = pts[0], pts[-1]
        tp, vp = max(pts, key=lambda p: p[1])
        trend = "RISING" if v1 > v0 * 1.5 and v1 - v0 > 1 else "FALLING" if v1 < v0 / 1.5 else "stable"
        return f"{args['metric']}: {v0} at {t0} → {v1} at {t1} (peak {vp} at {tp}) — {trend}"

    if capability == "alerts.list":
        return " · ".join(f"{a['name']} [{a['status']} since {a['since']}]" for a in data["alerts"]) or "no active alerts"

    if capability == "deploys.list":
        cur = data.get("current")
        now = f" (running {cur['version']} since {cur['since']})" if cur else ""
        return (" · ".join(f"{d['version']} at {d['time']} (was {d['previous']})" for d in data["deploys"])
                or "no deploys in window") + now

    if capability == "k8s.pods":
        return _pods(data)

    if capability == "k8s.events":
        if not data["total"]:
            return "no pod events"
        reasons = ", ".join(f"{n}× {r}" for r, n in sorted(data["reasons"].items(), key=lambda x: -x[1]))
        return f"{data['total']} events · first {data['first']} · {reasons}"

    if capability == "traces.search":
        if not data["count"]:
            return "no spans"
        ops = ", ".join(f"{_clip(n, 40)} {p}ms" for n, p in data["slowest_ops"])
        db = f" · db p99 {data['db_p99_ms']}ms" if data.get("db_p99_ms") is not None else ""
        return f"{data['count']} spans · p99 {data['p99_ms']}ms · {data['error_count']} errors · slowest: {ops}{db}"

    return str(data)[:200]
