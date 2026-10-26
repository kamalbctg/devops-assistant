"""Runs investigations in the background and stores them.

One investigation = one LangGraph thread (thread_id = investigation id).
Graph state lives in the checkpointer; the investigation row (status,
steps, report, audit) lives in the database so it survives restarts.
The agent and its connectors are loaded fresh from the database for every
run, so edits in the UI apply to the next investigation.
"""

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable

from langgraph.types import Command

from incident_agent.agent.graph import build_graph
from incident_agent.agent.nodes import AgentContext
from incident_agent.agent.planner import Planner
from incident_agent.config.agent_config import (
    DEFAULT_RETENTION,
    build_agent,
    retention_values,
)
from incident_agent.config.llm import llm_label, make_planner
from incident_agent.persistence.store import Store, new_id
from incident_agent.security.gateway import Gateway
from incident_agent.security.secrets import SecretBox
from incident_agent.service.events import describe, to_jsonable

DAY = 86400
PURGE_EVERY_S = 3600


class LimitReached(Exception):
    """The agent already keeps its maximum number of investigations."""


DATA_KEYS = ("events", "interrupt", "report", "verdict", "result", "error", "audit", "prompt_version")


@dataclass
class Run:
    id: str
    agent_id: str
    agent_name: str
    question: str
    source: str  # chat | datadog | alertmanager
    status: str = "running"  # running | waiting_input | done | failed
    created: float = field(default_factory=time.time)
    dedup_key: str | None = None
    events: list[dict] = field(default_factory=list)
    interrupt: dict | None = None
    report: str | None = None
    verdict: dict | None = None
    result: dict | None = None
    error: str | None = None
    audit: list[dict] = field(default_factory=list)
    prompt_version: int | None = None  # saved version of the agent's instructions when the run loaded them
    ctx: AgentContext | None = field(default=None, repr=False)

    def row(self) -> dict:
        return {"id": self.id, "agent_id": self.agent_id, "agent_name": self.agent_name, "question": self.question,
                "source": self.source, "status": self.status, "created": self.created, "dedup_key": self.dedup_key,
                "data": to_jsonable({k: getattr(self, k) for k in DATA_KEYS})}

    @classmethod
    def from_row(cls, row: dict) -> "Run":
        return cls(**{k: row[k] for k in ("id", "agent_id", "agent_name", "question", "source", "status",
                                         "created", "dedup_key")}, **row["data"])


def public(row: dict, with_events: bool = True) -> dict:
    d = {k: row[k] for k in ("id", "agent_id", "question", "source", "status", "created")}
    d["agent"] = row["agent_name"]
    data = row["data"]
    d.update({k: data.get(k) for k in ("interrupt", "report", "verdict", "result", "error", "prompt_version")})
    if with_events:
        d["events"], d["audit"] = data.get("events", []), data.get("audit", [])
    return d


class InvestigationService:
    def __init__(self, store: Store, box: SecretBox, planner_factory: Callable[[], Planner] | None = None,
                 checkpointer=None, max_workers: int = 4, test_connections: bool = True):
        """planner_factory overrides each agent's model choice (tests); None = use the agent's LLM setting."""
        self.store, self.box = store, box
        self.planner_factory = planner_factory
        self.test_connections = test_connections
        self.graph = build_graph(checkpointer)
        self.active: dict[str, Run] = {}
        self.pool = ThreadPoolExecutor(max_workers=max_workers)
        self._start_lock = threading.Lock()
        self._fail_interrupted()
        self.purge_expired()
        self._stop = threading.Event()
        threading.Thread(target=self._purge_loop, name="purge-investigations", daemon=True).start()

    # ---- retention ----

    def purge_expired(self) -> int:
        """Delete investigations (and their checkpoints) older than their agent keeps them. Runs of deleted
        agents use the default. Running investigations are never deleted."""
        keep = {a["id"]: retention_values(a.get("retention"))["keep_days"] for a in self.store.list_agents()}
        now, n = time.time(), 0
        for row in self.store.finished_before(now - DAY):  # one day is the shortest retention
            if row["created"] < now - keep.get(row["agent_id"], DEFAULT_RETENTION["keep_days"]) * DAY:
                self._remove(row["id"])
                n += 1
        return n

    def _purge_loop(self) -> None:
        while not self._stop.wait(PURGE_EVERY_S):
            try:
                self.purge_expired()
            except Exception:  # noqa: BLE001 — database briefly down: try again next hour
                pass

    def _remove(self, run_id: str) -> None:
        self.active.pop(run_id, None)
        self.graph.checkpointer.delete_thread(run_id)
        self.store.delete_investigation(run_id)

    def _fail_interrupted(self) -> None:
        """Runs live in this process's thread pool: one still "running" in the database was cut off by a
        restart and will never finish. Assumes one app instance per database."""
        for row in self.store.list_investigations(limit=None, status="running"):
            run = Run.from_row(row)
            run.status, run.error = "failed", "interrupted: the server restarted during the investigation"
            self.store.save_investigation(run.row())

    # ---- routing ----

    def agent_for_service(self, service: str) -> dict | None:
        """An agent that lists the service explicitly wins over an "all services" agent."""
        agents = self.store.list_agents()
        service = service.lower()
        return (next((a for a in agents if service in {s.lower() for s in a["services"]}), None)
                or next((a for a in agents if not a["services"]), None))

    def recent_duplicate(self, key: str, window_s: int = 1800) -> dict | None:
        rows = self.store.recent_by_dedup(key, time.time() - window_s)
        return rows[0] if rows else None

    # ---- reads ----

    def get(self, run_id: str) -> dict | None:
        run = self.active.get(run_id)
        return run.row() if run else self.store.get_investigation(run_id)

    def list(self, agent_id: str | None = None) -> list[dict]:
        return self.store.list_investigations(agent_id=agent_id)

    # ---- lifecycle ----

    def _context(self, run: Run) -> AgentContext:
        row = self.store.get_agent(run.agent_id)
        if row is None:
            raise ValueError("agent was deleted")
        planner = self.planner_factory() if self.planner_factory else make_planner(row.get("llm"), self.store, self.box)
        agent = build_agent(row, self.store, self.box, test_connections=self.test_connections)
        in_use = self.store.prompt_version(run.agent_id)  # record which saved version the run uses (not pinned)
        run.prompt_version = in_use["version"] if in_use else None
        agent.llm_label = "test planner" if self.planner_factory else llm_label(row.get("llm"))
        return AgentContext(agent=agent, gateway=Gateway(agent), planner=planner)

    def start(self, question: str, agent_id: str, source: str = "chat", dedup_key: str | None = None) -> dict:
        agent = self.store.get_agent(agent_id)
        if agent is None:
            raise KeyError(agent_id)
        limits = retention_values(agent.get("retention"))
        run = Run(id=new_id(), agent_id=agent_id, agent_name=agent["name"], question=question,
                  source=source, dedup_key=dedup_key)
        with self._start_lock:  # count + insert together: two starts never both take the last slot
            used = self.store.count_investigations(agent_id)
            if used >= limits["max_investigations"]:
                raise LimitReached(f"{agent['name']} already keeps {used} of {limits['max_investigations']} investigations. "
                                   f"Delete old ones, or wait until they expire ({limits['keep_days']} days).")
            self.active[run.id] = run
            self.store.save_investigation(run.row())
        self.pool.submit(self._drive, run, {"question": question})
        return run.row()

    def resume(self, run_id: str, answer: str) -> dict:
        row = self.get(run_id)
        if row is None:
            raise KeyError(run_id)
        if row["status"] != "waiting_input":
            raise ValueError(f"investigation is {row['status']}, not waiting for input")
        run = self.active.get(run_id) or Run.from_row(row)  # after a restart: rebuilt from the database
        run.status, run.interrupt = "running", None
        self.active[run.id] = run
        self.store.save_investigation(run.row())
        self.pool.submit(self._drive, run, Command(resume=answer))
        return run.row()

    def delete(self, run_id: str) -> None:
        """Remove the investigation and its graph checkpoints. A running one cannot be deleted."""
        row = self.get(run_id)
        if row is None:
            raise KeyError(run_id)
        if row["status"] == "running":
            raise ValueError("investigation is still running")
        self._remove(run_id)

    def _step(self, run: Run, node: str, text: str, update: dict | None = None) -> None:
        run.events.append({"t": time.time(), "node": node, "text": text, "update": to_jsonable(update or {})})
        run.audit = list(run.ctx.gateway.audit) if run.ctx else run.audit
        self.store.save_investigation(run.row())

    def _drive(self, run: Run, payload) -> None:
        config = {"configurable": {"thread_id": run.id}}
        try:
            if run.ctx is None:
                run.ctx = self._context(run)
                agent = run.ctx.agent
                text = (f"model: {agent.llm_label}\n"
                        f"connectors: {', '.join(f'{c.type} ({c.mode})' for c in agent.connectors) or 'none'}")
                if agent.skipped:
                    text += "\nskipped: " + "; ".join(agent.skipped)
                if agent.warnings:
                    text += "\nwarning: " + "; ".join(agent.warnings)
                self._step(run, "connect", text)
                if not agent.connectors:
                    raise RuntimeError("no usable connectors — test them on the Connectors page")
            for event in self.graph.stream(payload, config, context=run.ctx, stream_mode="updates"):
                for node, update in event.items():
                    if node != "__interrupt__":
                        update = update or {}  # a node that changed nothing streams None
                        text = describe(node, update)
                        if text is not None:
                            self._step(run, node, text, update)
            state = self.graph.get_state(config)
            if state.interrupts:
                run.status, run.interrupt = "waiting_input", state.interrupts[0].value
            else:
                v = state.values
                run.report = v.get("report")
                run.verdict = to_jsonable(v.get("verdict"))
                run.result = to_jsonable({
                    "scope": v.get("scope"), "hypotheses": list((v.get("hypotheses") or {}).values()),
                    "evidence": v.get("evidence", []), "tool_calls_used": v.get("tool_calls_used"),
                    "turns": v.get("turns"), "stop_reason": v.get("stop_reason"), "triage": v.get("triage"), "report": v.get("report_data"),
                    "analysis": v.get("analysis"),
                })
                run.status = "done"
        except Exception as e:  # never lose a run silently
            run.status, run.error = "failed", f"{type(e).__name__}: {e}"
        finally:
            run.audit = list(run.ctx.gateway.audit) if run.ctx else run.audit
            self.store.save_investigation(run.row())
            if run.status in ("done", "failed"):
                self.active.pop(run.id, None)
