"""Tool gateway: the only path from the agent to a data source.

Policy lives here, in plain code — not in the prompt and not in the framework:
  * capability must be configured for this agent
  * service must be inside the agent's scope
  * every call is written to the audit log
The model can ask for anything; the gateway decides.
"""

import re
import time
from dataclasses import dataclass, field

from incident_agent.config.agent_config import AgentConfig
from incident_agent.connectors import ConnectorError, RawResult

# Service names go into PromQL, Datadog and Alertmanager filters: no quotes, spaces or operators.
SERVICE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


class PolicyDenied(Exception):
    pass


@dataclass
class Gateway:
    agent: AgentConfig
    audit: list[dict] = field(default_factory=list)

    def call(self, capability: str, args: dict) -> RawResult:
        entry = {"ts": time.time(), "agent": self.agent.name, "capability": capability, "args": args}
        try:
            if not SERVICE_NAME.match(str(args.get("service") or "")):
                raise PolicyDenied(f"invalid service name {args.get('service')!r}")
            if not self.agent.covers(args.get("service")):
                raise PolicyDenied(f"service {args.get('service')!r} is outside this agent's scope")
            connectors = self.agent.connectors_for(capability)
            if not connectors:
                raise PolicyDenied(f"no connector configured for {capability}")
            # All connectors are equal: with several, the call says which one (no hidden priority or fallback;
            # a failure goes back to the model, which can choose another).
            name = args.get("connector")
            if name:
                connectors = [c for c in connectors if c.name == name]
                if not connectors:
                    raise PolicyDenied(f"connector {name!r} does not provide {capability} for this agent")
            elif len(connectors) > 1:
                raise PolicyDenied(f"several connectors provide {capability}: choose one of "
                                   f"{[c.name for c in connectors]}")
            result = connectors[0].query(capability, {k: v for k, v in args.items() if k != "connector"})
            entry.update(decision="allow", connector=result.connector, native_query=result.native_query)
            return result
        except (PolicyDenied, ConnectorError) as e:
            entry.update(decision="deny", reason=str(e))
            raise
        finally:
            self.audit.append(entry)
