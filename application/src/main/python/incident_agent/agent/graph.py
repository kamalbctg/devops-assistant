"""The LangGraph graph. START HERE.

    START → intake ─┬─(Send ×N)→ baseline_query ─→ triage ─┬─→ investigate ⟲ ─→ verify → analyze → report → END
                    ├────────────────────────────→ triage   └─→ verify   (no affected service found)
                    └────────────────────────────────────────→ verify   (refused / out of scope)

When the question names no service, the baseline sweeps every service the
agent covers and `triage` picks the affected one.

Fixed start (intake, baseline) and fixed end (verify, report) are plain
edges = workflow. `analyze` fills the agent's post-investigation analysis
fields (skipped when the agent has none). `investigate` loops on itself = ReAct. The conditional
edge after it is the stop rule.
"""

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
from langgraph.graph import END, START, StateGraph
from langgraph.types import Send

from incident_agent.agent.nodes import (
    AgentContext,
    analyze,
    baseline_query,
    intake,
    investigate,
    report,
    triage,
    verify,
)
from incident_agent.agent.state import InvestigationState


def after_intake(state: InvestigationState):
    """LANGGRAPH CONCEPT — Send (map/fan-out)
    Returning a list of Send(...) runs `baseline_query` once per task, in
    parallel, each with its own input. Their outputs merge via the reducer
    on `evidence`, then the graph continues to `investigate` once.
    """
    if state.get("refused"):
        return "verify"
    tasks = state.get("baseline_tasks", [])
    if not tasks:
        return "triage"
    return [Send("baseline_query", t) for t in tasks]


def after_triage(state: InvestigationState) -> str:
    return "verify" if state.get("stop_reason") else "investigate"


def after_investigate(state: InvestigationState) -> str:
    """LANGGRAPH CONCEPT — conditional edge
    A function of the state that names the next node. This is the loop:
    keep investigating until the node sets a stop reason.
    """
    return "verify" if state.get("stop_reason") else "investigate"


# Our Pydantic state types, allowed to be restored from checkpoints.
SERDE = JsonPlusSerializer(allowed_msgpack_modules=[
    ("incident_agent.agent.state", name) for name in ("Scope", "Evidence", "Hypothesis", "Conclusion", "Verdict")
])


def build_graph(checkpointer=None):
    g = StateGraph(InvestigationState, context_schema=AgentContext)

    g.add_node("intake", intake)
    g.add_node("baseline_query", baseline_query)
    g.add_node("triage", triage)
    g.add_node("investigate", investigate)
    g.add_node("verify", verify)
    g.add_node("analyze", analyze)
    g.add_node("report", report)

    g.add_edge(START, "intake")
    g.add_conditional_edges("intake", after_intake, ["baseline_query", "triage", "verify"])
    g.add_edge("baseline_query", "triage")
    g.add_conditional_edges("triage", after_triage, ["investigate", "verify"])
    g.add_conditional_edges("investigate", after_investigate, ["investigate", "verify"])
    g.add_edge("verify", "analyze")
    g.add_edge("analyze", "report")
    g.add_edge("report", END)

    # LANGGRAPH CONCEPT — checkpointer
    # Saves state after every step, keyed by thread_id. Needed for interrupt/
    # resume and for replaying a run. Use PostgresSaver in production.
    return g.compile(checkpointer=checkpointer or InMemorySaver(serde=SERDE))
