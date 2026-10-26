"""Agent types the platform offers. Each type is a different kind of agent
(its own graph and rules); users create agents of a type in the UI.

For now there is one: the read-only Incident Investigation Agent.
"""

from incident_agent.agent.prompts import DEFAULT_INSTRUCTIONS, SAFETY_RULES
from incident_agent.connectors.base import CAPABILITIES

AGENT_TYPES = {
    "incident_investigation": {
        "type": "incident_investigation",
        "label": "Incident Investigation",
        "icon": "🔎",
        "description": "Finds the most likely root cause of an incident from alerts, metrics, logs, traces, "
                       "deploys and pod events. Read-only: it never changes anything.",
        "capabilities": CAPABILITIES,
        "default_prompt": DEFAULT_INSTRUCTIONS.strip(),
        "safety_rules": SAFETY_RULES,
        "examples": ["Checkout is slow since 10:04", "Why is checkout returning errors since 10:04?",
                     "Everything is slow since 10:04"],
    },
}

DEFAULT_TYPE = "incident_investigation"
