"""Fake telemetry for one incident: "Checkout is slow since 10:04".

Story (the truth the agent should find):
    09:58  checkout v2.8.0 deployed
    09:59  checkout pods start throwing OutOfMemoryError, get OOMKilled
    10:04  p99 latency alert fires
    The database is fine — a tempting but wrong hypothesis.

Every connector in demo-data mode ("fake") reads from here, whatever its
type, so any mix of connectors sees the same incident.
"""

ALERTS = [
    {"service": "checkout", "name": "checkout p99 latency > 800ms", "status": "ALERT", "since": "10:04"},
    {"service": "checkout", "name": "checkout error rate > 2%", "status": "ALERT", "since": "10:05"},
]

# (time, value) series per service and metric
METRICS = {
    ("checkout", "latency_p99_ms"): [("09:50", 210), ("09:55", 220), ("10:00", 480), ("10:04", 1310), ("10:10", 1450)],
    ("checkout", "error_rate_pct"): [("09:50", 0.2), ("09:55", 0.2), ("10:00", 1.1), ("10:04", 4.1), ("10:10", 4.8)],
    ("checkout", "memory_pct"): [("09:50", 58), ("09:55", 61), ("10:00", 93), ("10:04", 97), ("10:10", 96)],
    ("checkout", "cpu_pct"): [("09:50", 38), ("09:55", 40), ("10:00", 44), ("10:04", 47), ("10:10", 45)],
    ("checkout", "db_latency_ms"): [("09:50", 11), ("09:55", 12), ("10:00", 12), ("10:04", 11), ("10:10", 12)],
}

LOGS = (
    [{"time": f"09:59:{12 + i % 40:02d}" if i < 40 else "10:0" + str(min(9, i // 45)) + ":00",
      "service": "checkout", "level": "ERROR",
      "message": "java.lang.OutOfMemoryError: Java heap space"} for i in range(388)]
    + [{"time": "10:03:40", "service": "checkout", "level": "WARN",
        "message": "timeout calling payment-gateway after 1000ms"}] * 121
    + [{"time": "10:01:00", "service": "checkout", "level": "INFO", "message": "order placed"}] * 900
    + [{"time": "10:02:00", "service": "payment", "level": "INFO", "message": "charge ok"}] * 500
)

TRACES = {
    "checkout": {"count": 5210, "p99_ms": 1420.0, "error_count": 214,
                 "slowest_ops": [["POST /checkout", 1420.0], ["payment-gateway call", 1105.0], ["cart lookup", 38.0]],
                 "db_p99_ms": 11.0},
}

DEPLOYS = [
    {"service": "checkout", "version": "v2.8.0", "time": "09:58:10", "previous": "v2.7.3", "by": "ci-pipeline"},
    {"service": "payment", "version": "v5.1.2", "time": "07:12:00", "previous": "v5.1.1", "by": "ci-pipeline"},
]

# pod health now: v2.8.0 pods keep getting OOMKilled (exit 137) and back off
PODS = {
    "checkout": {"desired": 4, "pods": [
        {"pod": f"checkout-7d9f-{i}", "phase": "Running", "ready": i > 1, "restarts": 4 - i,
         "waiting": "CrashLoopBackOff" if i == 1 else None,
         "last_exit": {"reason": "OOMKilled", "exit_code": 137, "at": f"10:0{i}:12"}, "node": "pool-a-1"}
        for i in range(1, 5)]},
    "payment": {"desired": 2, "pods": [
        {"pod": f"payment-5c4b-{i}", "phase": "Running", "ready": True, "restarts": 0, "waiting": None,
         "last_exit": None, "node": "pool-a-2"} for i in range(1, 3)]},
}

K8S_EVENTS = (
    [{"time": "09:59:40", "service": "checkout", "reason": "OOMKilled", "object": f"pod/checkout-7d9f-{i}"} for i in range(14)]
    + [{"time": "10:00:05", "service": "checkout", "reason": "BackOff", "object": "pod/checkout-7d9f-3"}] * 3
)
