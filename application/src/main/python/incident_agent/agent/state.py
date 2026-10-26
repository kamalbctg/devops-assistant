"""Graph state: the single typed object that flows between nodes.

LANGGRAPH CONCEPT — State
    Every node receives the current state and returns a *partial update*
    (a dict with only the keys it changed). LangGraph merges the update
    into the state. By default a key is overwritten; a key annotated with a
    *reducer* (e.g. `operator.add`) is combined instead. That is how several
    nodes running in parallel can all append evidence without clobbering
    each other.
"""

import operator
import re
from datetime import datetime, timedelta, timezone
from typing import Annotated, Literal, TypedDict
from zoneinfo import ZoneInfo

from pydantic import BaseModel, Field, field_validator

_HHMM = re.compile(r"\b([01]?\d|2[0-3]):([0-5]\d)\b")


def normalize_since(value: str | None) -> str | None:
    """'HH:MM' from what the model wrote ('10:04', '10:04:30', 'at 9:05'); ISO timestamps pass through.
    None when there is no usable time."""
    if not value:
        return None
    if "T" in value:
        return value
    m = _HHMM.search(value)
    return f"{int(m.group(1)):02d}:{m.group(2)}" if m else None


def clamp_window(since_iso: str, until_iso: str | None, since: str | None, until: str | None, tz: str) -> dict:
    """A past incident's window, narrowed to what the model asked for and never wider.

    since_iso/until_iso: the alert's window (timestamps). since/until: the model's HH:MM in the agent's
    timezone (the same clock the evidence summaries use), or timestamps. Returns ISO since and until.
    """
    lo = datetime.fromisoformat(since_iso)
    hi = datetime.fromisoformat(until_iso) if until_iso else datetime.now(timezone.utc)

    def at(value, default):
        if not value:
            return default
        if "T" in value:
            return datetime.fromisoformat(value)
        h, m = map(int, value.split(":"))
        t = lo.astimezone(ZoneInfo(tz)).replace(hour=h, minute=m, second=0, microsecond=0)
        return t + timedelta(days=1) if t < lo - timedelta(hours=12) else t  # window across midnight

    s, u = min(max(at(since, lo), lo), hi), min(max(at(until, hi), lo), hi)
    if u <= s:  # empty or reversed: the whole window
        s, u = lo, hi
    return {"since": s.isoformat(), "until": u.isoformat()}


class Scope(BaseModel):
    """What the incident is about. Produced by the intake node."""

    service: str | None = Field(None, description="Affected service, e.g. 'checkout'")
    symptom: str = Field(..., description="Short symptom, e.g. 'slow', 'errors', 'down'")
    since: str | None = Field(None, description="When it started, HH:MM (24h); null if not stated")
    until: str | None = None  # ISO end of window for past incidents (from an alert link); None = now
    alert: dict | None = None  # monitor details when the question was an alert link

    @field_validator("since", mode="before")
    @classmethod
    def _since(cls, v):
        return normalize_since(v)


class Evidence(BaseModel):
    """One summarized tool result. The model only ever sees `summary`."""

    id: str
    capability: str  # generic capability, e.g. "logs.search"
    connector: str  # which connector answered, e.g. "elasticsearch"
    args: dict = {}  # generic tool arguments the model sent
    native_query: str  # what the adapter actually ran (for humans / audit)
    summary: str  # one line: counts, top items, first seen
    hypothesis: str | None = None  # hypothesis id this query was testing
    anomalous: bool = False  # active alerts, rising metric, error hits, pod events
    when: str | None = None  # earliest time in the result (first log hit, deploy time, alert start) for the timeline
    data: dict | None = None  # structured result, kept only for small safe shapes (pod health) — never logs


class Hypothesis(BaseModel):
    id: str
    statement: str
    status: Literal["open", "supported", "ruled_out"] = "open"
    evidence_ids: list[str] = []


class Conclusion(BaseModel):
    """What the investigate loop claims when it calls `finish`.
    kind "root_cause": why something is wrong (needs >= 2 signal types).
    kind "answer": a direct answer to a focused question (logs, status) — needs >= 1 evidence."""

    kind: Literal["root_cause", "answer"] = "root_cause"
    cause_hypothesis: str = ""
    cause_service: str = ""
    summary: str
    evidence_ids: list[str]
    confidence: Literal["HIGH", "MEDIUM", "LOW"]
    impact: str = ""
    recommendations: list[str] = []


class Verdict(BaseModel):
    """What the verifier accepts after checking the conclusion."""

    status: Literal["root_cause_found", "answered", "inconclusive", "out_of_scope"]
    conclusion: Conclusion | None = None
    confidence: Literal["HIGH", "MEDIUM", "LOW"] = "LOW"
    independent_signals: list[str] = []
    not_checked: list[str] = []
    problems: list[str] = []


class InvestigationState(TypedDict, total=False):
    # input
    question: str
    # intake
    scope: Scope
    refused: str | None
    baseline_tasks: list["BaselineTask"]
    triage: dict | None  # when no service was named: which services were checked, which is affected
    # evidence — reducer: parallel baseline nodes append, they never overwrite
    evidence: Annotated[list[Evidence], operator.add]
    # investigate loop
    hypotheses: dict[str, Hypothesis]
    tool_calls_used: int
    turns: int
    notes: list[str]  # feedback for the model's next turn (bad call, finish rejected, ...)
    conclusion: Conclusion | None
    stop_reason: str | None
    stale_turns: int  # turns in a row without new evidence; the loop stops at MAX_STALE_TURNS
    reasoning: Annotated[list[dict], operator.add]  # per turn: {"turn", "model", "text"}; kept, never sent back
    # end
    verdict: Verdict
    analysis: list[dict] | None  # post-investigation analysis fields (model-extracted, type-checked)
    report: str
    report_data: dict


class BaselineTask(TypedDict, total=False):
    """Input for one parallel baseline query (sent with the Send API)."""

    id: str
    capability: str
    args: dict
    triage: bool  # part of the "which service is affected?" sweep
    keep: bool  # full check of a few services: keep healthy results too (shows each connector was checked)
