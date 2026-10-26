"""Demo data: created on first start (SEED_DEMO=true) so the UI works
without any credentials. Demo connectors run in fake mode against
scenario.py. Delete them in the UI once real connectors are added."""

from incident_agent.config.agent_config import agent_values, connector_values

DEMO_CONNECTORS = [
    {"name": "Demo Datadog", "type": "datadog", "mode": "fake",
     "provides": ["alerts.list", "metrics.query", "traces.search"], "settings": {"site": "datadoghq.eu"}},
    {"name": "Demo Elasticsearch", "type": "elasticsearch", "mode": "fake",
     "settings": {"url": "https://es.demo.local:9200", "indices": ["app-logs-*"], "message_keyword_field": "message.keyword"}},
    {"name": "Demo GKE", "type": "gke", "mode": "fake",
     "settings": {"project": "demo-project", "location": "europe-west1", "cluster": "prod",
                  "namespaces": ["checkout", "payment", "cart"]}},
]


def seed_demo(store, box) -> None:
    if store.list_connectors() or store.list_agents():
        return
    ids = [store.create_connector({**connector_values(c, box), "status": "ok",
                                   "status_detail": "demo data"})["id"] for c in DEMO_CONNECTORS]
    store.create_agent(agent_values({
        "name": "Checkout incident agent (demo)", "type": "incident_investigation",
        "description": "Investigates checkout, payment and cart using Datadog, Elasticsearch and GKE (demo data).",
        "services": ["checkout", "payment", "cart"], "connector_ids": ids,
        "llm": {"model": "scripted"},  # demo works without an API key
    }, store))
