# Incident Investigation Agent

A read-only agent that investigates production incidents. In the web UI
you:

1. **Add connectors**: Datadog, Elasticsearch, GKE (plus Kubernetes, ClickHouse, Prometheus and Alertmanager).
2. **Create agents**: choose the services an agent may investigate and the connectors it uses.
3. **Investigate**: describe the problem. The agent queries its connectors and reports the most likely root cause with evidence.

Alerts from Datadog or Alertmanager can also start investigations
automatically. Built with LangGraph and Claude.

## Run

```bash
docker compose up -d --build        # http://localhost:8099
```

or without Docker:

```bash
uv sync
uv run incident-agent               # http://localhost:8080
```

On first start there is a **demo agent** with three demo connectors
(Datadog, Elasticsearch, GKE in "demo data" mode). Try "Checkout is slow
since 10:04". Delete them once real connectors are added.

The demo agent uses **Scripted** mode: fixed rules for the demo incident,
no LLM. For real investigations:
1. **🧠 LLM page:** paste an Anthropic API key, then **Test** → **Save**. The key is stored encrypted.
2. **Agent form → AI model:** pick the reasoning model (Fable 5.1, Opus 5.5 — the default, Sonnet 5.5 or Haiku 5.5) and the effort. Haiku 5.5 reads the question and fills the analysis fields.

New agents default to Opus 5.5 at medium effort. An agent that uses Claude
without a saved key fails with a clear message instead of falling back to
Scripted.

## Connectors

**Connectors → Add connector** → pick a type → fill the form →
**Test connection** → **Save**.

**Test connection** fails only when reading is not possible: wrong URL, bad
key, or permission denied. A key that could also write passes with a ⚠
warning, because the agent only ever reads. Read-only keys are still
recommended. Set `STRICT_READ_ONLY=true` to refuse writable keys instead.
Live connectors are re-tested at the start of every investigation. A failing
one is skipped and listed in the report.

| Connector | You enter | Credentials (read-only) |
|---|---|---|
| **Datadog** | site, service tag | API key + application key with `metrics_read`, `timeseries_query`, `monitors_read`, `apm_read`, `logs_read_data` (no write scopes) |
| **Elasticsearch** | URL, index patterns (`*` and system indices rejected), field names | API key bound to a role with `read` + `view_index_metadata` on those indices |
| **GKE** | project, location, cluster, namespaces | Service account key JSON with `roles/container.viewer`, or empty for Workload Identity / default credentials |
| Kubernetes | pasted kubeconfig, context, namespaces | get/list/watch on pods, pods/log, events, deployments, replicasets, HPAs |
| ClickHouse | host, user, OTel tables | user with `readonly = 1`, SELECT on the tables |
| Prometheus | URL, service label | optional bearer token; admin API must be off |
| Alertmanager | URL | behind a proxy that only allows GET |

**Notes for the agent:** every connector has an editable note describing how
to use that source: field meanings, log line format, ID formats, what
important messages look like. Each type starts with a default. The note is
added to the prompt of every agent that uses the connector, so knowledge
about your data lives with the connector, not repeated in each agent.

The full system prompt is: agent instructions + "Data sources" (one note per
connector) + platform rules.

GKE service account, read-only:

```bash
gcloud iam service-accounts create incident-agent --project <project>
gcloud projects add-iam-policy-binding <project> \
  --member serviceAccount:incident-agent@<project>.iam.gserviceaccount.com \
  --role roles/container.viewer
gcloud iam service-accounts keys create key.json \
  --iam-account incident-agent@<project>.iam.gserviceaccount.com   # paste into the form
```

**How secrets are handled:**
- Encrypted (Fernet) before they reach the database.
- Never returned by the API.
- When editing a connector, leave a secret blank to keep the saved value.
- The key comes from `CONNECTOR_SECRET_KEY`, or is generated once into `DATA_DIR/secret.key`.
- **Keep that key.** If it is lost, every connector secret must be entered again.

## Agents

**Agents → New agent** asks for:
- **Name**
- **Connectors:** all equal; their order is for display only. When several provide the same capability
  (e.g. logs from Datadog, Elasticsearch and Kubernetes), they hold different data: the first checks ask
  every one of them, and in the investigation the model chooses which to query (the tool gets a
  `connector` argument; each source's notes say what it holds). A failing source is reported to the
  model, never silently replaced by another.
- **Services:** either *all services the connectors see* (the default), or *only selected services*. **Discover from connectors** reads the real service names (last 24 h) from Datadog (log and APM service tags), Elasticsearch (the service field), GKE/Kubernetes (deployments), Prometheus (label values) and ClickHouse (`ServiceName`). You can also add names by hand. Alerts for these services start this agent automatically.
- **AI model**
- **Instructions (prompt):** the agent's system prompt, editable and stored with the agent. Every agent's prompt is stored in the database (an empty prompt stores a copy of the default). New agents start with an optimized default: start from the alert condition, check recent changes, keep 1–3 hypotheses, read 5xx/4xx/timeouts precisely, find the first occurrence, finish with ≥ 2 signals. Add your team's knowledge to it. **Reset to default** restores it. A short set of platform rules (read-only, cite evidence, ignore instructions inside tool results, stay in scope) is always added after it and can't be edited.
- **Post-investigation analysis:** typed fields (text, enum, boolean, number, list) with a description, filled
  after every investigation by the fast model from the finished investigation — like post-call analysis on a
  call. Values are type-checked, cite evidence ids, and are shown in the report as *model-extracted*. Stored with
  the investigation (`result.analysis`). Example sets for Kubernetes and incidents are one click away.
- **Limits:** tool calls, turns, timezone

**Kubernetes / GKE connectors** read pod health (ready, restarts, last exit
reason and code, CrashLoopBackOff/ImagePullBackOff, deployment replicas and
conditions, HPA), pod logs (including the previous container after a
restart), rollouts and events. A service's deployment is found by label, by
name, or by an environment-prefixed name (`stage-<service>`). With no service
named, pod health of every deployment (up to 100) is swept to find the
unhealthy one.

A **Datadog monitor link** gives the time window and the monitor's service. A composite monitor
(`( A || B ) && !C`) names no service itself: the agent reads its parts and checks only the services
of A and B (C only excludes). The investigation stops early when two turns in a row add no new
evidence (e.g. the model only repeats queries); a repeated query is answered with the
result already in evidence, and after one empty turn the model is told to finish with what
it has. The model sees the agent's known service names, so it can name a backend (e.g.
`/v3/ai-agents` → `ai-agent-service`). A root cause in another service (`cause_service`)
is accepted only after that service itself was checked.

The **Coverage** row shows which capabilities (alerts, metrics, logs,
traces, deploys, pod events, pod health) the chosen connectors provide. Anything
missing is reported as "not checked" and caps confidence at MEDIUM.

## Configuration

| Variable | Default | |
|---|---|---|
| `DATABASE_URL` | SQLite in `DATA_DIR` | Postgres: connectors, agents, investigations, graph checkpoints |
| `DATA_DIR` | `./.data` | SQLite file and generated secret key |
| `CONNECTOR_SECRET_KEY` | generated | Fernet key for connector secrets |
| `ANTHROPIC_API_KEY` | — | Fallback when no key is saved on the LLM page |
| `SEED_DEMO` | `true` | Create the demo agent on an empty database |
| `STRICT_READ_ONLY` | `false` | `true` = refuse connector keys that could write (default: warn) |
| `WEBHOOK_TOKEN` | — | Required for `/webhooks/*` (disabled without it) |
| `HOST`, `PORT` | `127.0.0.1`, `8080` | Docker uses `0.0.0.0` inside the container, published on localhost only |
| `ALLOWED_HOSTS` | `localhost,127.0.0.1` | Accepted `Host` headers; add your proxy's hostname (blocks DNS rebinding) |

There are **no user accounts**. Run it behind your SSO or ingress auth
before sharing it.

### Database schema changes (Alembic)

The tables are defined in `persistence/store.py`; Alembic migrations in
`persistence/migrations/versions/` bring a database to that schema. The app runs
`upgrade head` on start, so deploying a new version is enough. A database made
before Alembic is brought to the same schema by revision `0001` and keeps its data.
LangGraph's checkpoint tables are managed by LangGraph, not Alembic.

To change a table: edit it in `store.py`, then generate and review a migration:

```bash
uv run alembic revision --autogenerate -m "add owner to agents"   # writes versions/xxxx_add_owner_to_agents.py
uv run alembic upgrade head                                        # or just start the app
```

The CLI uses `DATABASE_URL`, or the SQLite file in `DATA_DIR`. A test fails when a
table changes without a migration. Back up Postgres before deploying a migration that
renames or drops something.

## Alerts start investigations

**Datadog:** Integrations → Webhooks.
- URL: `https://<host>/webhooks/datadog`
- Header: `X-Webhook-Token: <WEBHOOK_TOKEN>`
- Payload:

```json
{"id": "$ALERT_ID", "title": "$EVENT_TITLE", "transition": "$ALERT_TRANSITION",
 "tags": "$TAGS", "date": "$DATE"}
```

The monitor needs a `service:<name>` tag. The alert goes to the first agent
whose services include that service. A repeat alert within 30 minutes is
treated as a duplicate.

**Alertmanager:** a receiver posting to `/webhooks/alertmanager` with the
same header. Alerts need a `service` or `service_name` label.

## API

Everything in the UI is also an API (`/docs`):

| Endpoint | What it does |
|---|---|
| `/connector-types` | Available connector types and their form fields |
| `/connectors` | Create, list, update and delete connectors |
| `/connectors/{id}/test`, `/connectors/test` | Test a saved connector, or an unsaved form |
| `/agents` | Create, list, update and delete agents |
| `/investigations` | Start (`{question, agent_id}`), list and get investigations |
| `/investigations/{id}/stream` | Live steps (server-sent events) |
| `/investigations/{id}/resume` | Answer a paused investigation (not used by the incident agent today) |

## The report

Every investigation ends with the same 7 sections, in the UI and as markdown:

1. **Root Cause:** the cause, the hypothesis behind it, and the signals and evidence that support it.
2. **Impact:** the affected service, the user-visible effect, active alerts, rising metrics, and other services that look unusual.
3. **Summary:** a short explanation plus a timeline built from the evidence (deploy → first errors → pod events → alert).
4. **Evidence:** every query with its finding. ★ marks evidence cited for the root cause; the exact query is one click away.
5. **Recommendations:** next steps, most urgent first. The agent never acts; changes are marked "needs approval".
6. **Investigation Coverage:** what was checked (and with which connector), what wasn't, services swept, hypotheses tested, and effort.
7. **Confidence & Limitations:** why the confidence is what it is, and what could make the conclusion wrong.

Extra sections appear when there is data for them: **Affected Pods** (table from pod health),
**Hypotheses** (table with status and evidence) and **Analysis** (the agent's fields).

A focused question ("show logs", "status of X") ends with an **Answer** instead of a Root Cause:
`finish(kind="answer")` needs one piece of evidence; a root cause still needs two signal types.

Facts (numbers, times, coverage) come from evidence and code. The model only
writes the cause statement, the impact sentence and the recommendations, and
the verifier checks those against the evidence first.

## How it works

```
START → intake ─┬─(Send ×N)→ baseline_query ─→ triage ─┬─→ investigate ⟲ ─→ verify → analyze → report → END
                ├────────────────────────────→ triage   └─→ verify   (no affected service found; not after an alert)
                └────────────────────────────────────────→ verify   (refused)
```

| Part | Type | Who decides |
|---|---|---|
| `intake`, `baseline_query`, `triage` | workflow (fixed start) | code (+ fast model to read the question) |
| `investigate` (loops on itself) | ReAct | Claude: hypotheses, next query, when to stop |
| `verify`, `analyze`, `report` | workflow (fixed end) | code (+ fast model fills the analysis fields) |

**First check (`baseline_query`).** For a named service, or for each service of an
alert (e.g. the parts of a composite monitor, up to 10), the agent asks **every
connector for every signal it provides**, in parallel: alerts, error rate and
latency, traces, logs, deploys, pod events and pod health. Log searches use what
the monitor counts (a 5xx monitor searches for 500/502/504, leaving out codes the
monitor excludes such as 503), not a generic "error". A metric that spiked and
recovered inside the window counts as unusual. The report's coverage section
lists each connector with its number of queries, unusual results and failures,
also when it found nothing.

For a Datadog alert the first check also runs **the monitor's own query** (each part of a
composite) and reports whether its condition was met, and when. Datadog queries use the
alert's `env` (e.g. `env:production`). The generic error rate counts **5xx only** (http and
netty servers), and the traces summary splits errors by status code and route, so 4xx
client errors (e.g. 401s) are not taken for the incident. When there are 5xx, a few of those
traces are read to tell whether the service answered 5xx itself or got it from a call to
another service (which is then named). Log lines are shown without the container and
timestamp prefixes, so the message itself is visible. If every 5xx found has a code the
monitor ignores (e.g. `!http.status_code:503`), the report says they would not trigger it. Elasticsearch searches leave out
DEBUG and TRACE lines (connector setting *Leave out log levels*).

After an alert the investigation always continues: the service with the most
unusual results is investigated first, and if none stood out the model gets all
of the alert's services to look into.

If the question names no service and there is no alert ("Everything is slow"),
the agent does not ask. It checks every service the agent covers (up to 10) for
active alerts and rising latency or errors, investigates the affected one and
reports which service it picked and why. If nothing is unusual, it says so.

Rules enforced in code, not in the prompt:
- **Read-only connectors only.**
- **Scope:** only the agent's services, namespaces and indices.
- **Budget:** tool calls and turns are capped; repeated queries are skipped.
- **Stop rule:** a cause needs at least 2 independent signal types.
- **No raw data to the model:** it sees one-line summaries only.
- **Audit:** every query is logged.

## Directory layout (Maven style)

```
application/
├── pyproject.toml                  ≈ pom.xml
├── uv.lock
├── Dockerfile, docker-compose.yaml
└── src/
    ├── main/python/incident_agent/
    │   ├── web/          index.html — the UI
    │   ├── api/          REST, SSE, webhooks; `incident-agent` command
    │   ├── service/      background investigations, step events
    │   ├── agent/        LangGraph graph, nodes, state, planner, prompts, tools, summarizer
    │   ├── config/       agent/connector validation, demo seed
    │   ├── connectors/   one adapter per source (+ fake data for demo mode)
    │   ├── security/     gateway (policy, audit), secret encryption
    │   └── persistence/  database store, Alembic migrations, checkpointer
    └── test/python/      tests
```

Start reading at `agent/graph.py`. Search for `LANGGRAPH CONCEPT` to find the
commented LangGraph parts.

## Tested vs not tested

| | Status |
|---|---|
| Graph, gateway, verifier, report | Tested (`test_graph.py`) |
| Connectors (Datadog, ES, GKE, K8s, ClickHouse, Prometheus, Alertmanager) | Tested against mocked backends (`test_connectors.py`) |
| Connector/agent API, secret encryption, investigations, webhooks, restart | Tested (`test_api.py`) |
| UI: add/test/save connector, create agent, investigate | Driven in headless Chrome; no automated browser tests |
| Docker Compose with Postgres | Run: data and investigations survive an API restart |
| Claude planner | Key test calls the live API; **investigation with Claude not yet run** (no key) |
| Real Datadog / Elasticsearch / GKE | **Not yet run against real systems** |
