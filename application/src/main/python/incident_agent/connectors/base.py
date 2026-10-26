"""Connector base class and the normalized result shapes.

Every connector returns the SAME shape per capability, whatever the vendor.
The summarizer only knows these shapes:

    logs.search    {"total": int, "first_seen": "HH:MM:SS" | None, "top": [[message, count], ...]}
    metrics.query  {"points": [["HH:MM", float], ...]}
    alerts.list    {"alerts": [{"name": str, "status": str, "since": "HH:MM"}]}
    deploys.list   {"deploys": [{"version": str, "time": "HH:MM:SS", "previous": str | None}],
                    "current": {"version": str, "since": "YYYY-MM-DD HH:MM"} | None  (optional)}
    k8s.events     {"total": int, "first": "HH:MM:SS" | None, "reasons": {reason: count}}
    k8s.pods       {"total", "ready", "restarts", "recent_restarts": int, "waiting": {reason: count},
                    "pods": [{"pod", "phase", "ready", "restarts", "waiting", "last_exit": {"reason", "exit_code",
                    "at", "recent"} | None, "node"}], "deployment": {...} | None, "hpa": {...} | None,
                    "first_problem": "HH:MM:SS" | None}
    traces.search  {"count": int, "p99_ms": float | None, "error_count": int,
                    "slowest_ops": [[name, p99_ms], ...], "db_p99_ms": float | None,
                    optional: "server_errors": int (5xx), "errors_by": [[status_code, route, count], ...],
                    "downstream_5xx": {service: error_count}, "traces_checked": int}
    metrics.query  optional "threshold": float when the query is a monitor's own condition

Modes:
    live — real client calls
    fake — data from scenario.py; for demos and tests ("demo" in the UI)

Each connector class also describes its own form (LABEL, FIELDS, SECRETS) so
the UI can render "Add connector" without knowing the vendor.
"""

import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

CAPABILITIES = [
    "alerts.list",
    "metrics.query",
    "logs.search",
    "traces.search",
    "deploys.list",
    "k8s.events",
    "k8s.pods",
]

# Extra detail, not a separate signal area: an agent without it is not reported as having a gap
# (pod health refines pod events; both come from the same Kubernetes connector).
OPTIONAL_CAPABILITIES = {"k8s.pods"}

GENERIC_METRICS = ["latency_p99_ms", "error_rate_pct", "memory_pct", "cpu_pct", "db_latency_ms"]


def _describe(e: Exception) -> str:
    """Short error text; for HTTP errors the status plus the body's reason instead of a docs link."""
    response = getattr(e, "response", None)
    if response is not None and hasattr(response, "status_code"):
        return f"HTTP {response.status_code}: {(getattr(response, 'text', '') or '')[:300]}"
    return f"{type(e).__name__}: {e}"


class ConnectorError(Exception):
    pass


@dataclass
class RawResult:
    connector: str
    native_query: str
    data: dict[str, Any]


class Connector(ABC):
    type: str = "base"
    LABEL: str = "Base"
    capabilities: set[str] = set()  # what this source can serve; `provides` is the part enabled per connector
    # Form schema for the UI. Field: {key, label, type, required, default, help, options}
    #   type: text | number | bool | select | list (comma separated) | json
    FIELDS: list[dict] = []
    # Secret fields: stored encrypted, never returned by the API.
    SECRETS: list[dict] = []
    # How the agent should use this source. Added to the agent's prompt; editable per connector.
    DEFAULT_NOTES: str = ""

    @classmethod
    def schema(cls) -> dict:
        return {"type": cls.type, "label": cls.LABEL, "capabilities": sorted(cls.capabilities, key=CAPABILITIES.index),
                "fields": cls.FIELDS, "secrets": cls.SECRETS, "doc": (cls.__doc__ or "").strip(),
                "default_notes": cls.DEFAULT_NOTES.strip()}

    def __init__(self, provides: list[str], settings: dict | None = None, mode: str = "live", timezone: str = "UTC",
                 secrets: dict | None = None, name: str = "", notes: str | None = None):
        unknown = set(provides) - self.capabilities
        if unknown:
            raise ConnectorError(f"{self.type} cannot provide {sorted(unknown)}")
        if mode not in ("live", "fake"):
            raise ConnectorError(f"mode must be live or fake, got {mode!r}")
        self.provides = provides
        self.settings = settings or {}
        self.secrets = {k: v for k, v in (secrets or {}).items() if v}
        self.name = name or self.type
        self.notes = (notes or self.DEFAULT_NOTES).strip()
        self.mode = mode
        self.tz = ZoneInfo(timezone)
        self.validate_settings()

    # ---- configuration --------------------------------------------------------

    def validate_settings(self) -> None:
        """Reject unsafe scope at configuration time (e.g. '*' indices)."""

    def setting(self, key: str, default: Any = None) -> Any:
        if default is None and key not in self.settings:
            raise ConnectorError(f"{self.type}: missing setting {key!r}")
        return self.settings.get(key, default)

    def secret(self, key: str, required: bool = True) -> str | None:
        """Secret from the encrypted store, or from an env var named by settings `<key>_env`."""
        value = self.secrets.get(key)
        if not value and self.settings.get(f"{key}_env"):
            value = os.environ.get(self.settings[f"{key}_env"])
        if required and not value:
            raise ConnectorError(f"{self.type}: secret {key!r} is not set")
        return value

    # ---- connection test ---------------------------------------------------------

    def test_connection(self, strict: bool | None = None) -> list[str]:
        """Run when the connector is added and before each investigation.

        Fails only if reading is not possible (wrong URL, bad key, permission denied).
        A key that could also write passes with a warning — the agent only ever reads.
        With strict=True (or STRICT_READ_ONLY=true) such a key is refused instead.
        Returns the warnings.
        """
        if self.mode == "fake":
            return []
        if strict is None:
            strict = os.environ.get("STRICT_READ_ONLY", "false").lower() == "true"
        try:
            self.read_probe()
            writable = self.write_probe()
        except ConnectorError:
            raise
        except Exception as e:  # DNS, TLS, timeout, unexpected response
            raise ConnectorError(f"{self.type}: connection test failed: {type(e).__name__}: {e}") from e
        if writable and strict:
            raise ConnectorError(f"{self.type}: credentials allow writes — not read-only, refusing connector")
        return [f"{self.type}: key can also write — the agent only reads, but a read-only key is safer"] if writable else []

    @abstractmethod
    def read_probe(self) -> None:
        """Cheap read. Raise ConnectorError if it fails."""

    @abstractmethod
    def write_probe(self) -> bool:
        """Return True if writes are possible. Must not change anything."""

    # ---- querying ----------------------------------------------------------------

    def query(self, capability: str, args: dict) -> RawResult:
        if capability not in self.provides:
            raise ConnectorError(f"{self.type} is not configured for {capability}")
        native = self.native_query(capability, args)
        if self.mode == "fake":
            from .fake import fake_result

            return RawResult(self.name, native, fake_result(self.type, capability, args, self.settings))
        try:
            return RawResult(self.name, native, self.fetch(capability, args))
        except ConnectorError:
            raise
        except Exception as e:  # network, auth, bad response: report, never crash the run
            raise ConnectorError(f"{self.type} {capability} failed: {_describe(e)}") from e

    def list_services(self) -> list[str]:
        """Service names this source knows about (recent data). Used by "Discover services"
        and by agents that cover all services."""
        if self.mode == "fake":
            from . import scenario

            return sorted({r["service"] for r in scenario.LOGS} | {d["service"] for d in scenario.DEPLOYS})
        try:
            return sorted({s for s in self.discover_services() if s})
        except ConnectorError:
            raise
        except Exception as e:
            raise ConnectorError(f"{self.type}: service discovery failed: {type(e).__name__}: {e}") from e

    def discover_services(self) -> list[str]:
        return []

    @abstractmethod
    def native_query(self, capability: str, args: dict) -> str:
        """The query this source runs, as text. Goes to evidence and the audit log."""

    @abstractmethod
    def fetch(self, capability: str, args: dict) -> dict:
        """Run the query and return the normalized shape (see module docstring)."""

    # ---- time helpers ------------------------------------------------------------

    def window(self, args: dict) -> tuple[datetime, datetime]:
        """`since` is HH:MM in the agent's timezone (today, or yesterday if in the future),
        or an ISO timestamp for past incidents; optional ISO `until` (default now)."""
        now = datetime.now(self.tz)
        if "T" in args["since"]:
            start = datetime.fromisoformat(args["since"]).astimezone(self.tz)
            end = datetime.fromisoformat(args["until"]).astimezone(self.tz) if args.get("until") else now
            return start, min(end, now)
        h, m = map(int, args["since"].split(":"))
        start = now.replace(hour=h, minute=m, second=0, microsecond=0)
        if start > now:
            start -= timedelta(days=1)
        return start, now

    def hhmm(self, value: datetime | str | float | None, seconds: bool = False) -> str | None:
        if value is None:
            return None
        if isinstance(value, (int, float)):
            value = datetime.fromtimestamp(value, self.tz)
        elif isinstance(value, str):
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if value.tzinfo is None:
            value = value.replace(tzinfo=ZoneInfo("UTC"))
        return value.astimezone(self.tz).strftime("%H:%M:%S" if seconds else "%H:%M")


def downsample(points: list, n: int = 12) -> list:
    """At most n points: the first, the last, and the highest of each bucket between them,
    so a short spike survives (taking every k-th point can skip it)."""
    if len(points) <= n:
        return points
    inner, k = points[1:-1], n - 2
    size = len(inner) / k
    buckets = [inner[int(i * size):int((i + 1) * size)] for i in range(k)]
    return [points[0], *(max(b, key=lambda p: p[1]) for b in buckets if b), points[-1]]
