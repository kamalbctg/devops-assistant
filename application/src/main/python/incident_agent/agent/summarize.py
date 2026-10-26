"""Summarizer: normalized connector result -> one line the model can read.

Whole results never reach the model (cost, prompt injection, secrets): only these
lines, where a few example log messages are cut short and personal data and
credentials in them are masked (redact). This version is plain code; swap in a
fast model (Haiku) when results get fuzzy.
"""


import re

# container runtime prefix (`<ts> stdout F `), the app's own timestamp, empty MDC brackets `[] [] []`
_LOG_NOISE = [re.compile(r"^b['\"]"), re.compile(r"^\S+Z\s+(?:stdout|stderr)\s+[FP]\s+"),
              re.compile(r"^\d{4}-\d{2}-\d{2}[T ][\d:.]+Z?\s+"), re.compile(r"(?:\[\]\s*)+")]


def _clip(s: str, n: int = 70) -> str:
    s = " ".join(str(s).split())
    return s if len(s) <= n else s[: n - 1] + "…"


# Personal data and credentials in log text: masked before the line reaches the model, the database or the UI.
# Order matters: whole tokens (JWT, key=value) before the shorter patterns inside them.
_REDACT = [
    (re.compile(r"\beyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]*"), "[jwt]"),
    (re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|app[_-]?key|access[_-]?key|authorization)"
                r"(\"?\s*[:=]\s*\"?)(?:(?:bearer|basic)\s+)?[^\s\"',;&}]+"), r"\1\2[secret]"),
    (re.compile(r"(?i)\b(bearer|basic)\s+[\w.~+/=-]{8,}"), r"\1 [secret]"),
    (re.compile(r"[\w.%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}"), "[email]"),
    (re.compile(r"(?<![\w.:])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])"), "[ip]"),
    (re.compile(r"(?i)(?<![\w:])(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}(?![\w:])"), "[ip]"),
    # card / account numbers: 15-19 digits (a 13-digit epoch-ms timestamp stays)
    (re.compile(r"(?<![\w-])(?:\d[ -]?){14,18}\d(?![\w-])"), "[number]"),
    (re.compile(r"(?<![\w+/])\+\d{8,14}(?!\w)"), "[phone]"),
    # long keys and base64 blobs: upper, lower and digits mixed, no "/" (pod names, hex ids, SHAs and URL paths stay)
    (re.compile(r"(?<![\w/+=-])(?=[\w+-]*[A-Z])(?=[\w+-]*[a-z])(?=[\w+-]*\d)[A-Za-z0-9+_-]{32,}={0,2}(?![\w/+=-])"),
     "[secret]"),
]


def redact(s: str) -> str:
    """Mask emails, IP addresses, tokens, `password=...` values and long numbers or keys in free text."""
    for pattern, repl in _REDACT:
        s = pattern.sub(repl, s)
    return s


def clean_log(line: str, n: int = 200) -> str:
    """A log line without the prefixes that carry no meaning, so the message itself fits; personal data masked."""
    s = str(line)
    for pattern in _LOG_NOISE:
        s = pattern.sub("", s, count=0 if pattern.pattern.startswith("(?:") else 1)
    return _clip(redact(s.rstrip("'\"")), n)


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


def metric_trend(pts: list) -> str:
    """RISING (ends well above the start), SPIKE (peak well above both ends: it rose and recovered),
    FALLING or stable."""
    (_, v0), (_, v1) = pts[0], pts[-1]
    vp = max(v for _, v in pts)
    if v1 > v0 * 1.5 and v1 - v0 > 1:
        return "RISING"
    if vp > max(v0, v1) * 1.5 and vp - max(v0, v1) > 1:
        return "SPIKE"
    return "FALLING" if v1 < v0 / 1.5 else "stable"


def crossed(data: dict, args: dict) -> list:
    """Points where a monitor condition was met (value op threshold)."""
    if "threshold" not in data:
        return []
    op, th = args.get("op", ">="), data["threshold"]
    test = {">=": lambda v: v >= th, ">": lambda v: v > th, "<=": lambda v: v <= th, "<": lambda v: v < th}[op]
    return [p for p in data["points"] if test(p[1])]


def summarize(capability: str, data: dict, args: dict) -> str:
    if capability == "logs.search":
        if not data["total"]:
            return "0 hits"
        if data["top"] and data["top"][0][1] is None:  # example lines (plain-text message field)
            return f"{data['total']} hits · first seen {data['first_seen']} · e.g. " + " | ".join(clean_log(m) for m, _ in data["top"])
        tops = "; ".join(f"{n}× {clean_log(m, 120)}" for m, n in data["top"])
        return f"{data['total']} hits · first seen {data['first_seen']} · top: {tops or '-'}"

    if capability == "metrics.query":
        pts = data["points"]
        if not pts:
            return f"{args['metric']}: no data"
        (t0, v0), (t1, v1) = pts[0], pts[-1]
        tp, vp = max(pts, key=lambda p: p[1])
        if args["metric"] == "alert_condition":
            hit = crossed(data, args)
            cond = f"alert condition of monitor {args.get('monitor_id')} ({args.get('op')} {data.get('threshold')})"
            return (f"{cond}: MET {len(hit)}× from {hit[0][0]} to {hit[-1][0]}, peak {vp} at {tp}" if hit else
                    f"{cond}: not met in the window (peak {vp} at {tp})")
        trend = metric_trend(pts)
        if trend == "SPIKE":
            return f"{args['metric']}: SPIKE to {vp} at {tp} ({v0} at {t0} → {v1} at {t1}, recovered)"
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
        errors = f"{data['error_count']} errors"
        if "server_errors" in data:  # what the errors are: 4xx = client, 5xx = server
            by = "; ".join(f"{n}× {code} {_clip(str(r), 45)}" for code, r, n in data.get("errors_by", []))
            errors += f" (5xx: {data['server_errors']}" + (f" · {by}" if by else "") + ")"
        if data.get("server_errors") and "downstream_5xx" in data:  # where the 5xx came from, from sample traces
            down = data["downstream_5xx"]
            errors += (" · 5xx traces call: " + ", ".join(f"{s} ({n} err)" for s, n in down.items()) if down else
                       f" · 5xx answered by {args.get('service', 'the service')} itself: no downstream call in "
                       f"{data.get('traces_checked', 0)} sample trace(s)")
        return f"{data['count']} spans · p99 {data['p99_ms']}ms · {errors} · slowest (not errors): {ops}{db}"

    return str(data)[:200]
