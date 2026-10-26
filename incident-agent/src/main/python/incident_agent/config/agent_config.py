"""Agents and connectors as configured in the UI.

A connector = a saved connection to one data source (Datadog, Elasticsearch,
GKE, ...). An agent = a name, the services it may investigate, and the
connectors it reads from. Both live in the database; this module validates
UI input and turns saved rows into runnable objects.
"""

import json
from dataclasses import dataclass, field
from zoneinfo import ZoneInfo

from incident_agent.agent.analysis import fields_values
from incident_agent.agent.prompts import DEFAULT_INSTRUCTIONS
from incident_agent.config.agent_types import AGENT_TYPES, DEFAULT_TYPE
from incident_agent.config.llm import SCRIPTED, llm_label, llm_values
from incident_agent.connectors import CONNECTOR_TYPES, Connector, ConnectorError
from incident_agent.connectors.base import CAPABILITIES, OPTIONAL_CAPABILITIES
from incident_agent.security.secrets import SecretBox


@dataclass
class Budget:
    max_tool_calls: int = 12
    max_turns: int = 8


@dataclass
class AgentConfig:
    name: str
    services: list[str]
    connectors: list[Connector]
    budget: Budget = field(default_factory=Budget)
    timezone: str = "UTC"
    id: str = ""
    description: str = ""
    skipped: list[str] = field(default_factory=list)  # connectors left out of this run, with reason
    warnings: list[str] = field(default_factory=list)  # e.g. a key that could also write
    llm_label: str = ""
    prompt: str | None = None  # agent instructions (stored per agent); None only for agents built in code
    analysis_fields: list[dict] = field(default_factory=list)  # post-investigation analysis (agent/analysis.py)
    _known: list[str] | None = field(default=None, repr=False)  # cache for known_services()

    def connector_for(self, capability: str) -> Connector | None:
        """Any connector that provides the capability (all are equal; used to know what is covered)."""
        return next(iter(self.connectors_for(capability)), None)

    def connector_choices(self, capability: str) -> list[str]:
        """Names to choose from when several connectors provide the capability; [] when there is one."""
        names = [c.name for c in self.connectors_for(capability)]
        return names if len(names) > 1 else []

    def connectors_for(self, capability: str) -> list[Connector]:
        return [c for c in self.connectors if capability in c.provides]

    @property
    def all_services(self) -> bool:
        return not self.services

    def covers(self, service: str | None) -> bool:
        return bool(service) and (self.all_services or service.lower() in {s.lower() for s in self.services})

    def known_services(self) -> list[str]:
        """The explicit list, or — for "all services" — what the connectors report (read once per run)."""
        if self.services:
            return self.services
        if self._known is None:
            found: set[str] = set()
            for c in self.connectors:
                try:
                    found |= set(c.list_services())
                except ConnectorError as e:
                    self.warnings.append(str(e))
            self._known = sorted(found)
        return self._known

    @property
    def capabilities(self) -> list[str]:
        return [c for c in CAPABILITIES if self.connector_for(c)]

    @property
    def not_configured(self) -> list[str]:
        return [c for c in CAPABILITIES if not self.connector_for(c) and c not in OPTIONAL_CAPABILITIES]


# ---------------------------------------------------------------- connectors

MAX_PROMPT = 20000

# Investigation history per agent: kept at most 7 days, at most 100 at a time (lower per agent if wanted).
MAX_KEEP_DAYS, MAX_INVESTIGATIONS = 7, 100
DEFAULT_RETENTION = {"keep_days": MAX_KEEP_DAYS, "max_investigations": MAX_INVESTIGATIONS}


def retention_values(data: dict | None) -> dict:
    """{"keep_days": 1–7, "max_investigations": 1–100}; missing keys take the maximum. Raises ValueError."""
    merged = {**DEFAULT_RETENTION, **{k: v for k, v in (data or {}).items() if v not in (None, "")}}
    try:
        r = {k: int(merged[k]) for k in DEFAULT_RETENTION}
    except (TypeError, ValueError) as e:
        raise ValueError("retention: days and max investigations must be numbers") from e
    if not 1 <= r["keep_days"] <= MAX_KEEP_DAYS:
        raise ValueError(f"retention: keep investigations 1–{MAX_KEEP_DAYS} days")
    if not 1 <= r["max_investigations"] <= MAX_INVESTIGATIONS:
        raise ValueError(f"retention: max investigations 1–{MAX_INVESTIGATIONS}")
    return r

def make_connector(row: dict, box: SecretBox, timezone: str = "UTC") -> Connector:
    cls = CONNECTOR_TYPES[row["type"]]
    return cls(row["provides"], row["settings"], mode=row["mode"], timezone=timezone, secrets=box.decrypt(row["secrets"]),
               name=row.get("name", ""), notes=row.get("notes"))


def _parse_field(f: dict, value):
    kind = f.get("type", "text")
    if value is None or value == "":
        return None
    if kind == "list":
        items = value if isinstance(value, list) else str(value).split(",")
        return [str(i).strip() for i in items if str(i).strip()] or None
    if kind == "number":
        try:
            return int(value)
        except (TypeError, ValueError) as e:
            raise ValueError(f"{f['label']}: must be a number") from e
    if kind == "bool":
        return value if isinstance(value, bool) else str(value).lower() in ("1", "true", "yes", "on")
    if kind == "json":
        if isinstance(value, dict):
            return value or None
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError as e:
            raise ValueError(f"{f['label']}: invalid JSON ({e.msg})") from e
        if not isinstance(parsed, dict):
            raise ValueError(f"{f['label']}: must be a JSON object")
        return parsed or None
    if kind == "select" and f.get("options") and value not in f["options"]:
        raise ValueError(f"{f['label']}: must be one of {f['options']}")
    return str(value).strip()


def connector_values(data: dict, box: SecretBox, existing: dict | None = None) -> dict:
    """Validate a connector form and return the row to store. Raises ValueError."""
    ctype = data.get("type") or (existing or {}).get("type")
    cls = CONNECTOR_TYPES.get(ctype)
    if cls is None:
        raise ValueError(f"unknown connector type {ctype!r}")
    name = (data.get("name") or "").strip()
    if not name:
        raise ValueError("name is required")
    mode = data.get("mode", "live")
    if mode not in ("live", "fake"):
        raise ValueError("mode must be live or fake")
    provides = data.get("provides") or sorted(cls.capabilities, key=CAPABILITIES.index)
    if not set(provides) <= cls.capabilities:
        raise ValueError(f"{cls.LABEL} can provide only {sorted(cls.capabilities)}")

    raw = data.get("settings") or {}
    settings = {}
    for f in cls.FIELDS:
        value = _parse_field(f, raw.get(f["key"]))
        if value is None:
            value = f.get("default") or None
        if value is None and f.get("required") and mode == "live":
            raise ValueError(f"{f['label']} is required")
        if value is not None:
            settings[f["key"]] = value

    secrets = box.decrypt((existing or {}).get("secrets"))
    for s in cls.SECRETS:
        new = (data.get("secrets") or {}).get(s["key"])
        if new:  # blank = keep the stored value
            secrets[s["key"]] = new.strip()
        if s.get("required") and mode == "live" and not secrets.get(s["key"]):
            raise ValueError(f"{s['label']} is required")

    try:  # the class checks scope rules too (e.g. no '*' index)
        cls(provides, settings, mode=mode, secrets=secrets)
    except ConnectorError as e:
        raise ValueError(str(e)) from e
    notes = (data.get("notes") or "").strip()
    if not notes or notes == cls.DEFAULT_NOTES.strip():
        notes = None  # follows the type default
    elif len(notes) > MAX_PROMPT:
        raise ValueError(f"notes are too long ({len(notes)} > {MAX_PROMPT} characters)")
    return {"name": name, "type": ctype, "mode": mode, "provides": provides, "settings": settings,
            "secrets": box.encrypt(secrets), "notes": notes}


def public_connector(row: dict, box: SecretBox, used_by: list[str] | None = None) -> dict:
    """What the API returns: everything except secret values."""
    cls = CONNECTOR_TYPES[row["type"]]
    stored = box.decrypt(row["secrets"])
    out = {k: row.get(k) for k in ("id", "name", "type", "mode", "provides", "settings", "status",
                               "status_detail", "tested_at", "created_at", "updated_at")}
    out["label"] = cls.LABEL
    out["notes"] = (row.get("notes") or cls.DEFAULT_NOTES).strip()
    out["notes_is_default"] = not row.get("notes")
    out["secrets_set"] = [s["key"] for s in cls.SECRETS if stored.get(s["key"])]
    out["used_by"] = used_by or []
    return out


# ---------------------------------------------------------------- agents

def prompt_value(text: str | None) -> str:
    """The instructions stored with the agent. Empty = a copy of the default, so every agent's prompt is in
    the database and a later change of the default never changes an existing agent."""
    text = (text or "").strip() or DEFAULT_INSTRUCTIONS.strip()
    if len(text) > MAX_PROMPT:
        raise ValueError(f"instructions are too long ({len(text)} > {MAX_PROMPT} characters)")
    return text


def agent_values(data: dict, store) -> dict:
    """Validate an agent form. Raises ValueError."""
    name = (data.get("name") or "").strip()
    if not name:
        raise ValueError("name is required")
    atype = data.get("type") or DEFAULT_TYPE
    if atype not in AGENT_TYPES:
        raise ValueError(f"unknown agent type {atype!r}")
    services = data.get("services") or []
    if isinstance(services, str):
        services = services.split(",")
    services = list(dict.fromkeys(s.strip() for s in services if s.strip()))  # empty = all services
    ids = data.get("connector_ids") or []
    if not ids:
        raise ValueError("choose at least one connector")
    missing = [i for i in ids if store.get_connector(i) is None]
    if missing:
        raise ValueError(f"unknown connectors: {missing}")
    b = data.get("budget") or {}
    try:
        budget = {"max_tool_calls": int(b.get("max_tool_calls", 12)), "max_turns": int(b.get("max_turns", 8))}
    except (TypeError, ValueError) as e:
        raise ValueError("budget: tool calls and turns must be numbers") from e
    if not (1 <= budget["max_tool_calls"] <= 50 and 1 <= budget["max_turns"] <= 30):
        raise ValueError("budget: tool calls 1–50, turns 1–30")
    tz = data.get("timezone") or "UTC"
    try:
        ZoneInfo(tz)
    except Exception as e:
        raise ValueError(f"unknown timezone {tz!r}") from e
    return {"name": name, "type": atype, "description": (data.get("description") or "").strip(), "services": services,
            "connector_ids": list(dict.fromkeys(ids)), "budget": budget, "timezone": tz,
            "llm": llm_values(data.get("llm")), "prompt": prompt_value(data.get("prompt")),
            "analysis_fields": fields_values(data.get("analysis_fields")),
            "retention": retention_values(data.get("retention"))}


def public_agent(row: dict, store) -> dict:
    in_use = store.prompt_version(row["id"])
    conns = [store.get_connector(i) for i in row["connector_ids"]]
    conns = [c for c in conns if c]
    covered = {cap for c in conns for cap in c["provides"]}
    t = AGENT_TYPES.get(row.get("type") or DEFAULT_TYPE, AGENT_TYPES[DEFAULT_TYPE])
    return {**{k: row[k] for k in ("id", "name", "description", "services", "connector_ids", "budget",
                                   "timezone", "created_at", "updated_at")},
            "type": t["type"], "type_label": t["label"], "icon": t["icon"],
            "llm": llm_values(row.get("llm")), "llm_label": llm_label(llm_values(row.get("llm"))),
            "analysis_fields": row.get("analysis_fields") or [],
            "retention": retention_values(row.get("retention")),
            "prompt_version": in_use["version"] if in_use else None,
            "prompt": row.get("prompt") or DEFAULT_INSTRUCTIONS.strip(), "prompt_is_default": (row.get("prompt") or "").strip() in ("", DEFAULT_INSTRUCTIONS.strip()),
            "warnings": (["Scripted mode uses fixed demo rules — choose a Claude model for real data"]
                         if llm_values(row.get("llm"))["model"] == SCRIPTED and any(c["mode"] == "live" for c in conns) else []),
            "connectors": [{"id": c["id"], "name": c["name"], "type": c["type"], "mode": c["mode"],
                            "status": c["status"], "provides": c["provides"]} for c in conns],
            "not_configured": [c for c in CAPABILITIES if c not in covered and c not in OPTIONAL_CAPABILITIES]}


def discover_services(connector_rows: list[dict], box: SecretBox) -> dict:
    """{"services": [...], "sources": {connector name: count or error}}"""
    found, sources = set(), {}
    for row in connector_rows:
        try:
            names = make_connector(row, box).list_services()
            found |= set(names)
            sources[row["name"]] = len(names)
        except (ConnectorError, ValueError) as e:
            sources[row["name"]] = str(e)
    return {"services": sorted(found), "sources": sources}


def build_agent(row: dict, store, box: SecretBox, test_connections: bool = True) -> AgentConfig:
    """Saved agent -> runnable config. Live connectors are re-tested on every run:
    a connector that fails or turns out writable is left out (and reported)."""
    agent = AgentConfig(id=row["id"], name=row["name"], description=row.get("description") or "",
                        services=row["services"], connectors=[], budget=Budget(**row["budget"]),
                        timezone=row["timezone"], prompt=row.get("prompt"),
                        analysis_fields=row.get("analysis_fields") or [])
    for cid in row["connector_ids"]:
        crow = store.get_connector(cid)
        if crow is None:
            agent.skipped.append(f"{cid}: connector was deleted")
            continue
        try:
            conn = make_connector(crow, box, row["timezone"])
            if test_connections:
                agent.warnings += conn.test_connection()
            agent.connectors.append(conn)
        except (ConnectorError, ValueError) as e:
            agent.skipped.append(f"{crow['name']}: {e}")
    return agent
