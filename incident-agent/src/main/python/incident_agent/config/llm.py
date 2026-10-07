"""LLM choice: one Anthropic API key for the platform (LLM settings page),
and a model choice per agent (agent form)."""

import os

MODELS = [
    {"id": "claude-opus-5-5", "label": "Claude Opus 5.5", "note": "best reasoning", "effort": True},
    {"id": "claude-sonnet-5-5", "label": "Claude Sonnet 5.5", "note": "strong, cheaper", "effort": True},
    {"id": "claude-haiku-4-5", "label": "Claude Haiku 4.5", "note": "fastest, cheapest", "effort": False},
]
SCRIPTED = "scripted"  # fixed rules for the demo incident, no LLM
EFFORTS = ["low", "medium", "high"]
DEFAULT_LLM = {"model": "claude-opus-5-5", "fast_model": "claude-haiku-4-5", "effort": "medium"}
MODEL_IDS = {m["id"] for m in MODELS}


def llm_values(data: dict | None) -> dict:
    llm = {**DEFAULT_LLM, **(data or {})}
    if llm["model"] != SCRIPTED and llm["model"] not in MODEL_IDS:
        raise ValueError(f"unknown model {llm['model']!r}")
    if llm["fast_model"] not in MODEL_IDS:
        raise ValueError(f"unknown fast model {llm['fast_model']!r}")
    if llm["effort"] not in EFFORTS:
        raise ValueError(f"effort must be one of {EFFORTS}")
    return {k: llm[k] for k in DEFAULT_LLM}


def llm_label(llm: dict | None) -> str:
    llm = llm or DEFAULT_LLM
    if llm["model"] == SCRIPTED:
        return "Scripted (no LLM, demo only)"
    m = next(x for x in MODELS if x["id"] == llm["model"])
    return f"{m['label']}" + (f" · {llm['effort']} effort" if m["effort"] else "")


def anthropic_key(store, box) -> tuple[str | None, str]:
    """(key, source). The key saved in the UI wins over the ANTHROPIC_API_KEY env var."""
    row = store.get_setting("llm")
    saved = box.decrypt(row["secrets"]).get("api_key") if row else None
    if saved:
        return saved, "saved in UI"
    env = os.environ.get("ANTHROPIC_API_KEY")
    return (env, "environment") if env else (None, "not set")


def workspace_id(store) -> str | None:
    """Needed only for API keys that are not scoped to a workspace."""
    row = store.get_setting("llm")
    return (row["value"].get("workspace_id") if row else None) or os.environ.get("ANTHROPIC_WORKSPACE_ID") or None


def anthropic_headers(ws: str | None) -> dict:
    return {"anthropic-workspace-id": ws} if ws else {}


def make_planner(llm: dict | None, store, box):
    from incident_agent.agent.planner import ClaudePlanner, ScriptedPlanner

    llm = llm or DEFAULT_LLM
    if llm["model"] == SCRIPTED:
        return ScriptedPlanner()
    key, _ = anthropic_key(store, box)
    if not key:
        raise ValueError("no Anthropic API key — add it on the LLM page, or switch this agent to Scripted")
    effort = llm["effort"] if next(m for m in MODELS if m["id"] == llm["model"])["effort"] else None
    return ClaudePlanner(strong=llm["model"], fast=llm["fast_model"], effort=effort, api_key=key,
                         headers=anthropic_headers(workspace_id(store)))


def test_anthropic_key(key: str, ws: str | None = None) -> dict:
    import anthropic

    try:
        anthropic.Anthropic(api_key=key, timeout=20, default_headers=anthropic_headers(ws)).models.list(limit=1)
        return {"ok": True, "detail": "API key works" + (f" (workspace {ws})" if ws else "")}
    except anthropic.AuthenticationError:
        return {"ok": False, "detail": "invalid API key (401)"}
    except anthropic.PermissionDeniedError:
        return {"ok": False, "detail": "permission denied (403)"}
    except anthropic.BadRequestError as e:
        if "workspace" in str(e):
            return {"ok": False, "detail": "this key is not scoped to a workspace — enter the Workspace ID "
                                           "(Console → Workspaces), or create the key inside a workspace"}
        return {"ok": False, "detail": f"bad request: {e}"}
    except Exception as e:
        return {"ok": False, "detail": f"{type(e).__name__}: {e}"}
