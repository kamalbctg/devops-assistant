"""Understand alert links pasted as the question.

Datadog monitor notification link, e.g.
  https://app.datadoghq.com/monitors/264260680?group=env%3Aproduction&from_ts=…&to_ts=…&event_ts=…
gives the monitor id (→ name, service tag, state via the Datadog connector)
and the alert time (→ the investigation window).
"""

import re
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, unquote, urlparse

LINK = re.compile(r"https://app\.(?:[a-z0-9]+\.)?datad(?:oghq|og)\.[a-z.]+/monitors/(\d+)[^\s]*")


def parse_datadog_link(text: str) -> dict | None:
    m = LINK.search(text or "")
    if not m:
        return None
    q = parse_qs(urlparse(m.group(0)).query)

    def ts(key):
        try:
            return datetime.fromtimestamp(int(q[key][0]) / 1000, timezone.utc)
        except (KeyError, ValueError, IndexError):
            return None

    alert_at = ts("event_ts") or ts("link_event_ts") or ts("to_ts")
    start = ts("from_ts")
    end = ts("to_ts")
    group = {k: v for k, v in (p.split(":", 1) for p in unquote(q.get("group", [""])[0]).split(",") if ":" in p)}
    return {"monitor_id": m.group(1), "alert_at": alert_at, "from": start, "to": end, "group": group}


def window_from_link(link: dict) -> tuple[str, str]:
    """ISO start/end: 30 min before the alert (or the link's from_ts) until 30 min after."""
    at = link["alert_at"] or link["to"] or datetime.now(timezone.utc)
    start = min(filter(None, [link["from"], at - timedelta(minutes=30)]))
    end = min(max(filter(None, [link["to"], at + timedelta(minutes=30)])), datetime.now(timezone.utc))
    start = min(start, end - timedelta(minutes=5))  # clock skew: never an empty window
    return start.isoformat(timespec="seconds"), end.isoformat(timespec="seconds")


def symptom_from(name: str) -> str:
    n = name.lower()
    for words, symptom in ((("latency", "slow", "p99", "p95", "duration"), "slow"),
                           (("error", "5xx", "exception", "fail"), "errors"),
                           (("down", "unavailable", "health", "crash", "restart", "oom"), "down"),
                           (("cpu", "memory", "disk", "saturation"), "resource pressure")):
        if any(w in n for w in words):
            return symptom
    return "alert"
