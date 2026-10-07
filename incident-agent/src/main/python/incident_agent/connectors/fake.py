"""Fake mode: answers from scenario.py in the normalized shapes."""

from collections import Counter

from . import scenario


def _after(t: str, since: str) -> bool:
    return t[:5] >= (since[11:16] if "T" in since else since)


def fake_result(connector: str, capability: str, args: dict, settings: dict) -> dict:
    svc, since = args["service"], args["since"]

    if capability == "logs.search":
        q = (args.get("query") or "").lower()
        rows = [r for r in scenario.LOGS if r["service"] == svc and _after(r["time"], since)
                and (not q or q in r["message"].lower() or q == r["level"].lower())]
        top = Counter(r["message"] for r in rows).most_common(3)
        return {"total": len(rows), "first_seen": min((r["time"] for r in rows), default=None),
                "top": [[m, n] for m, n in top]}

    if capability == "metrics.query":
        return {"points": [[t, v] for t, v in scenario.METRICS.get((svc, args["metric"]), [])]}

    if capability == "alerts.list":
        return {"alerts": [{k: a[k] for k in ("name", "status", "since")} for a in scenario.ALERTS if a["service"] == svc]}

    if capability == "deploys.list":
        return {"deploys": [{k: d[k] for k in ("version", "time", "previous")}
                            for d in scenario.DEPLOYS if d["service"] == svc and _after(d["time"], since)]}

    if capability == "k8s.events":
        namespaces = settings.get("namespaces")
        if namespaces and svc not in namespaces:
            return {"total": 0, "first": None, "reasons": {}}
        rows = [e for e in scenario.K8S_EVENTS if e["service"] == svc and _after(e["time"], since)]
        return {"total": len(rows), "first": min((e["time"] for e in rows), default=None),
                "reasons": dict(Counter(e["reason"] for e in rows))}

    if capability == "k8s.pods":
        spec = scenario.PODS.get(svc) or {"desired": 0, "pods": []}
        pods = [{**p, "last_exit": p["last_exit"] and {**p["last_exit"], "recent": _after(p["last_exit"]["at"], since)}}
                for p in spec["pods"]]
        ready = sum(p["ready"] for p in pods)
        recent = [p["last_exit"]["at"] for p in pods if p["last_exit"] and p["last_exit"]["recent"]]
        return {"total": len(pods), "ready": ready, "restarts": sum(p["restarts"] for p in pods),
                "recent_restarts": len(recent), "waiting": dict(Counter(p["waiting"] for p in pods if p["waiting"])),
                "pods": pods, "deployment": {"name": svc, "desired": spec["desired"], "ready": ready, "available": ready,
                                             "updated": len(pods), "problems": []},
                "hpa": None, "first_problem": min(recent, default=None)}

    if capability == "traces.search":
        t = scenario.TRACES.get(svc)
        return t or {"count": 0, "p99_ms": None, "error_count": 0, "slowest_ops": [], "db_p99_ms": None}

    raise ValueError(capability)
