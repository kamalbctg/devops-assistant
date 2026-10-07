"""Web UI + HTTP API + alert webhooks.

    uv run incident-agent          # UI at http://localhost:8080, API docs at /docs

Environment:
    DATA_DIR              local data (SQLite db, generated secret key). Default ./.data
    DATABASE_URL          Postgres for connectors, agents, investigations and checkpoints
    CONNECTOR_SECRET_KEY  Fernet key that encrypts connector secrets (generated if unset)
    ANTHROPIC_API_KEY     fallback when no key is saved on the LLM page
    SEED_DEMO             create demo connectors + agent on an empty database (default true)
    STRICT_READ_ONLY      refuse connector keys that could write (default false: warn only)
    WEBHOOK_TOKEN         shared secret for /webhooks/* (webhooks are disabled without it)
    HOST, PORT            default 127.0.0.1:8080

There are no user accounts: run it behind your SSO proxy before sharing it.
"""

import asyncio
import hmac
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel

from incident_agent.config.agent_config import (
    agent_values,
    connector_values,
    discover_services,
    make_connector,
    public_agent,
    public_connector,
)
from incident_agent.config.agent_types import AGENT_TYPES
from incident_agent.config.demo import seed_demo
from incident_agent.config.llm import (
    EFFORTS,
    MODELS,
    anthropic_key,
    test_anthropic_key,
    workspace_id,
)
from incident_agent.connectors import CONNECTOR_TYPES, ConnectorError
from incident_agent.persistence.checkpoint import make_checkpointer
from incident_agent.persistence.store import Store, database_url
from incident_agent.security.secrets import SecretBox
from incident_agent.service.investigation_service import InvestigationService, public


class StartRequest(BaseModel):
    question: str
    agent_id: str


class ResumeRequest(BaseModel):
    answer: str


def create_app(store: Store | None = None, box: SecretBox | None = None,
               service: InvestigationService | None = None) -> FastAPI:
    data_dir = os.environ.get("DATA_DIR", ".data")
    store = store or Store(database_url(data_dir))
    box = box or SecretBox.from_env(data_dir)
    if os.environ.get("SEED_DEMO", "true").lower() == "true":
        seed_demo(store, box)
    service = service or InvestigationService(store, box, None, make_checkpointer())
    app = FastAPI(title="Incident Investigation Agent")

    def bad_request(e: Exception):
        raise HTTPException(400, str(e)) from e

    # ---------------------------------------------------------------- UI

    @app.get("/", include_in_schema=False)
    def ui():
        return FileResponse(Path(__file__).parent.parent / "web" / "index.html")

    @app.get("/healthz")
    def healthz():
        return {"ok": True, "agents": len(store.list_agents()), "connectors": len(store.list_connectors())}

    # ---------------------------------------------------------------- connectors

    @app.get("/connector-types")
    def connector_types():
        return [cls.schema() for cls in CONNECTOR_TYPES.values()]

    def connector_or_404(cid):
        row = store.get_connector(cid)
        if row is None:
            raise HTTPException(404, "connector not found")
        return row

    def present(row):
        return public_connector(row, box, [a["name"] for a in store.agents_using(row["id"])])

    def run_test(conn) -> dict:
        try:
            warnings = conn.test_connection()
            if conn.mode == "fake":
                detail = "demo data (fake mode)"
            elif warnings:
                detail = "read OK · ⚠ " + "; ".join(warnings)
            else:
                detail = "read OK · write refused (read-only)"
            return {"ok": True, "detail": detail, "warnings": warnings}
        except (ConnectorError, ValueError) as e:
            return {"ok": False, "detail": str(e)}

    @app.get("/connectors")
    def list_connectors():
        return [present(r) for r in store.list_connectors()]

    @app.post("/connectors", status_code=201)
    def create_connector(body: dict):
        try:
            values = connector_values(body, box)
        except ValueError as e:
            bad_request(e)
        if any(c["name"] == values["name"] for c in store.list_connectors()):
            raise HTTPException(409, f"a connector named {values['name']!r} already exists")
        return present(store.get_connector(store.create_connector(values)["id"]))

    @app.get("/connectors/{cid}")
    def get_connector(cid: str):
        return present(connector_or_404(cid))

    @app.put("/connectors/{cid}")
    def update_connector(cid: str, body: dict):
        existing = connector_or_404(cid)
        try:
            values = connector_values({**body, "type": existing["type"]}, box, existing)
        except ValueError as e:
            bad_request(e)
        if any(c["name"] == values["name"] and c["id"] != cid for c in store.list_connectors()):
            raise HTTPException(409, f"a connector named {values['name']!r} already exists")
        store.update_connector(cid, {**values, "status": "untested", "status_detail": None})
        return present(store.get_connector(cid))

    @app.delete("/connectors/{cid}", status_code=204)
    def delete_connector(cid: str):
        connector_or_404(cid)
        users = store.agents_using(cid)
        if users:
            raise HTTPException(409, f"used by agents: {', '.join(a['name'] for a in users)}")
        store.delete_connector(cid)

    @app.post("/connectors/{cid}/test")
    def test_saved_connector(cid: str):
        row = connector_or_404(cid)
        result = run_test(make_connector(row, box))
        store.update_connector(cid, {"status": "ok" if result["ok"] else "failed",
                                     "status_detail": result["detail"], "tested_at": time.time()})
        return result

    @app.post("/connectors/test")
    def test_unsaved_connector(body: dict):
        """Test a form before saving. With `id`, blank secrets reuse the stored ones."""
        existing = store.get_connector(body["id"]) if body.get("id") else None
        try:
            values = connector_values({**body, "name": body.get("name") or "test"}, box, existing)
        except ValueError as e:
            return {"ok": False, "detail": str(e)}
        return run_test(make_connector(values, box))

    # ---------------------------------------------------------------- LLM

    def llm_info():
        key, source = anthropic_key(store, box)
        return {"provider": "anthropic", "key_set": bool(key), "source": source,
                "workspace_id": workspace_id(store) or "", "models": MODELS, "efforts": EFFORTS}

    @app.get("/llm")
    def get_llm():
        return llm_info()

    @app.put("/llm")
    def put_llm(body: dict):
        """api_key: blank keeps the saved key. workspace_id: blank clears it."""
        row = store.get_setting("llm")
        secrets = box.decrypt(row["secrets"]) if row else {}
        key = (body.get("api_key") or "").strip() or secrets.get("api_key")
        if not key:
            raise HTTPException(400, "api_key is required")
        ws = (body.get("workspace_id") or "").strip()
        store.put_setting("llm", {"provider": "anthropic", "workspace_id": ws}, box.encrypt({"api_key": key}))
        return llm_info()

    @app.post("/llm/test")
    def test_llm(body: dict | None = None):
        body = body or {}
        key = (body.get("api_key") or "").strip() or anthropic_key(store, box)[0]
        if not key:
            return {"ok": False, "detail": "no API key saved"}
        ws = (body["workspace_id"].strip() if "workspace_id" in body else workspace_id(store)) or None
        return test_anthropic_key(key, ws)

    # ---------------------------------------------------------------- agents

    def agent_or_404(aid):
        row = store.get_agent(aid)
        if row is None:
            raise HTTPException(404, "agent not found")
        return row

    @app.get("/agent-types")
    def agent_types():
        return list(AGENT_TYPES.values())

    @app.get("/agents")
    def list_agents():
        return [public_agent(a, store) for a in store.list_agents()]

    @app.post("/agents", status_code=201)
    def create_agent(body: dict):
        try:
            values = agent_values(body, store)
        except ValueError as e:
            bad_request(e)
        if any(a["name"] == values["name"] for a in store.list_agents()):
            raise HTTPException(409, f"an agent named {values['name']!r} already exists")
        return public_agent(store.get_agent(store.create_agent(values)["id"]), store)

    @app.post("/services/discover")
    def services_discover(body: dict):
        """Service names seen by the given connectors (recent data). Read-only."""
        rows = [store.get_connector(i) for i in body.get("connector_ids", [])]
        return discover_services([r for r in rows if r], box)

    @app.get("/agents/{aid}")
    def get_agent(aid: str):
        return public_agent(agent_or_404(aid), store)

    @app.put("/agents/{aid}")
    def update_agent(aid: str, body: dict):
        agent_or_404(aid)
        try:
            values = agent_values(body, store)
        except ValueError as e:
            bad_request(e)
        if any(a["name"] == values["name"] and a["id"] != aid for a in store.list_agents()):
            raise HTTPException(409, f"an agent named {values['name']!r} already exists")
        store.update_agent(aid, values)
        return public_agent(store.get_agent(aid), store)

    @app.delete("/agents/{aid}", status_code=204)
    def delete_agent(aid: str):
        agent_or_404(aid)
        store.delete_agent(aid)

    # ---------------------------------------------------------------- investigations

    def run_or_404(run_id):
        row = service.get(run_id)
        if row is None:
            raise HTTPException(404, "investigation not found")
        return row

    @app.post("/investigations", status_code=201)
    def start(req: StartRequest):
        if not req.question.strip():
            raise HTTPException(400, "question is empty")
        try:
            return public(service.start(req.question.strip(), req.agent_id), with_events=False)
        except KeyError as e:
            raise HTTPException(404, "agent not found") from e

    @app.get("/investigations")
    def list_runs(agent_id: str | None = None):
        return [public(r, with_events=False) for r in service.list(agent_id)]

    @app.get("/investigations/{run_id}")
    def get_run(run_id: str):
        return public(run_or_404(run_id))

    @app.post("/investigations/{run_id}/resume")
    def resume(run_id: str, req: ResumeRequest):
        run_or_404(run_id)
        try:
            return public(service.resume(run_id, req.answer), with_events=False)
        except ValueError as e:
            raise HTTPException(409, str(e)) from e

    @app.get("/investigations/{run_id}/stream")
    async def stream(run_id: str):
        """Server-sent events: one per finished step, then the final status."""
        run_or_404(run_id)

        async def gen():
            sent = 0
            while True:
                row = service.get(run_id)
                events = row["data"].get("events", [])
                for e in events[sent:]:
                    yield f"event: step\ndata: {json.dumps({'node': e['node'], 'text': e['text']})}\n\n"
                sent = len(events)
                if row["status"] != "running":
                    yield f"event: {row['status']}\ndata: {json.dumps(public(row, with_events=False), default=str)}\n\n"
                    return
                await asyncio.sleep(0.3)

        return StreamingResponse(gen(), media_type="text/event-stream")

    # ---------------------------------------------------------------- webhooks

    def check_token(token: str | None):
        expected = os.environ.get("WEBHOOK_TOKEN")
        if not expected:
            raise HTTPException(503, "webhooks disabled: WEBHOOK_TOKEN not set")
        if not token or not hmac.compare_digest(token, expected):
            raise HTTPException(401, "bad webhook token")

    def trigger(service_name: str, title: str, started: datetime, source: str, key: str):
        agent = service.agent_for_service(service_name)
        if agent is None:
            return {"status": "ignored", "reason": f"no agent covers service {service_name!r}"}
        dup = service.recent_duplicate(key)
        if dup:
            return {"status": "duplicate", "investigation": dup["id"]}
        at = started.astimezone(ZoneInfo(agent["timezone"])).strftime("%H:%M")
        run = service.start(f"{title} — alert for {service_name} since {at}", agent["id"], source=source, dedup_key=key)
        return {"status": "started", "investigation": run["id"], "agent": agent["name"]}

    @app.post("/webhooks/datadog", status_code=202)
    def datadog_webhook(body: dict, x_webhook_token: str | None = Header(None)):
        """Datadog webhook payload template:
        {"id": "$ALERT_ID", "title": "$EVENT_TITLE", "transition": "$ALERT_TRANSITION",
         "tags": "$TAGS", "date": "$DATE"}
        """
        check_token(x_webhook_token)
        if body.get("transition") not in ("Triggered", "Re-Triggered"):
            return {"status": "ignored", "reason": f"transition {body.get('transition')!r}"}
        tags = dict(t.split(":", 1) for t in str(body.get("tags", "")).split(",") if ":" in t)
        svc = tags.get("service")
        if not svc:
            return {"status": "ignored", "reason": "no service:<name> tag on the monitor"}
        try:
            started = datetime.fromtimestamp(int(body["date"]) / 1000, timezone.utc)
        except (KeyError, ValueError, TypeError):
            started = datetime.now(timezone.utc)
        return trigger(svc, body.get("title", "Datadog alert"), started, "datadog", f"datadog:{body.get('id')}:{svc}")

    @app.post("/webhooks/alertmanager", status_code=202)
    def alertmanager_webhook(body: dict, x_webhook_token: str | None = Header(None)):
        """Standard Alertmanager webhook (version 4). One investigation per firing service."""
        check_token(x_webhook_token)
        results, seen = [], set()
        for alert in body.get("alerts", []):
            labels = alert.get("labels", {})
            svc = labels.get("service") or labels.get("service_name")
            if alert.get("status") != "firing" or not svc or svc in seen:
                continue
            seen.add(svc)
            started = datetime.fromisoformat(alert.get("startsAt", datetime.now(timezone.utc).isoformat()).replace("Z", "+00:00"))
            results.append(trigger(svc, labels.get("alertname", "Alert"), started, "alertmanager",
                                   f"alertmanager:{body.get('groupKey')}:{svc}"))
        return {"results": results} if results else {"status": "ignored", "reason": "no firing alerts with a service label"}

    return app


def main() -> None:
    import uvicorn

    # 127.0.0.1 by default: there are no user accounts. Docker sets HOST=0.0.0.0.
    uvicorn.run(create_app(), host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "8080")))
