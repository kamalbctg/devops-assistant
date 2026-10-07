"""Tool definitions the model can call.

Two kinds:
  * data tools — generic, stack-agnostic (logs_search, metrics_query, ...).
    Only the ones this agent has connectors for are offered to the model.
  * board tools — update the hypothesis board or finish the investigation.

Each tool is a Pydantic model: the JSON schema goes to the model, and the
same class validates the arguments the model sends back.
"""

from typing import Literal

from pydantic import BaseModel, Field


class _DataTool(BaseModel):
    service: str = Field(..., description="Service name, must be in scope")
    since: str = Field(..., description="Start of window, HH:MM")
    hypothesis: str = Field(..., description="Hypothesis id this query tests, e.g. H1")


class alerts_list(_DataTool):
    """List active alerts/monitors for the service."""


class metrics_query(_DataTool):
    """Read one metric time series for the service."""

    metric: Literal["latency_p99_ms", "error_rate_pct", "memory_pct", "cpu_pct", "db_latency_ms"]


class logs_search(_DataTool):
    """Search logs (log platform, or pod logs from Kubernetes incl. the previous container after a restart).
    Returns counts, first seen and the top messages."""

    query: str = Field("", description="Text to match, e.g. 'OutOfMemory', or a level like 'error'")


class traces_search(_DataTool):
    """Summarize slow traces: p99, where time is spent, db span latency."""


class deploys_list(_DataTool):
    """Recent deployments of the service."""


class k8s_events(_DataTool):
    """Kubernetes events for the service's deployment, ReplicaSets and pods (OOMKilled, BackOff, Killing,
    Unhealthy, FailedScheduling, Evicted) with counts and first time."""


class k8s_pods(_DataTool):
    """Pod health now: ready/total, restarts, last exit reason + code + time per pod (137 OOM/SIGKILL,
    143 SIGTERM, 1 app error), waiting reasons (CrashLoopBackOff, ImagePullBackOff), deployment replicas
    and failing conditions, HPA."""


class add_hypothesis(BaseModel):
    """Add a new hypothesis to the board."""

    statement: str


class set_hypothesis_status(BaseModel):
    """Mark a hypothesis supported or ruled out, citing evidence ids."""

    id: str
    status: Literal["supported", "ruled_out"]
    evidence_ids: list[str]


class finish(BaseModel):
    """Stop and give the result.
    kind="root_cause": the question asks why something is wrong — name the cause hypothesis; needs evidence
    from >= 2 independent signal types (e.g. pod health + logs).
    kind="answer": the question only asks for a fact (show logs, current status, did it restart?) — answer it
    directly in summary; needs >= 1 evidence id, no hypothesis."""

    kind: Literal["root_cause", "answer"] = Field("root_cause", description="root_cause or answer")
    cause_hypothesis: str = Field("", description="Hypothesis id, e.g. H1 (required for root_cause)")
    summary: str = Field(..., description="root_cause: what happened and why, 1-2 sentences. answer: the answer")
    evidence_ids: list[str]
    confidence: Literal["HIGH", "MEDIUM", "LOW"]
    impact: str = Field("", description="Who/what is affected and how badly, with numbers from evidence")
    recommendations: list[str] = Field(default_factory=list, description=(
        "2-4 concrete next steps, most urgent first. You cannot act: mark changes as 'needs approval'"))


DATA_TOOLS: dict[str, type[_DataTool]] = {
    "alerts.list": alerts_list,
    "metrics.query": metrics_query,
    "logs.search": logs_search,
    "traces.search": traces_search,
    "deploys.list": deploys_list,
    "k8s.events": k8s_events,
    "k8s.pods": k8s_pods,
}
TOOL_TO_CAPABILITY = {cls.__name__: cap for cap, cls in DATA_TOOLS.items()}
BOARD_TOOLS = {cls.__name__: cls for cls in (add_hypothesis, set_hypothesis_status, finish)}


def tools_for(capabilities: list[str]) -> list[type[BaseModel]]:
    """Only offer data tools this agent has connectors for, plus board tools."""
    return [DATA_TOOLS[c] for c in capabilities] + list(BOARD_TOOLS.values())


def anthropic_spec(cls: type[BaseModel]) -> dict:
    """Tool in Anthropic format: name, description, JSON schema."""
    return {"name": cls.__name__, "description": (cls.__doc__ or "").strip(),
            "input_schema": cls.model_json_schema()}
