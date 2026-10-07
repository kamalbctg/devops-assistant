"""Tool gateway: the only path from the agent to a data source.

Policy lives here, in plain code — not in the prompt and not in the framework:
  * capability must be configured for this agent
  * service must be inside the agent's scope
  * every call is written to the audit log
The model can ask for anything; the gateway decides.
"""

import time
from dataclasses import dataclass, field

from incident_agent.config.agent_config import AgentConfig
from incident_agent.connectors import ConnectorError, RawResult


class PolicyDenied(Exception):
    pass


@dataclass
class Gateway:
    agent: AgentConfig
    audit: list[dict] = field(default_factory=list)

    def call(self, capability: str, args: dict) -> RawResult:
        entry = {"ts": time.time(), "agent": self.agent.name, "capability": capability, "args": args}
        try:
            if not self.agent.covers(args.get("service")):
                raise PolicyDenied(f"service {args.get('service')!r} is outside this agent's scope")
            connectors = self.agent.connectors_for(capability)
            if not connectors:
                raise PolicyDenied(f"no connector configured for {capability}")
            errors = []
            for connector in connectors:  # agent order = priority; a failing source falls through to the next
                try:
                    result = connector.query(capability, args)
                except ConnectorError as e:
                    errors.append(str(e))
                    continue
                entry.update(decision="allow", connector=result.connector, native_query=result.native_query,
                             fallback_from=errors or None)
                return result
            raise ConnectorError(" | ".join(errors))
        except (PolicyDenied, ConnectorError) as e:
            entry.update(decision="deny", reason=str(e))
            raise
        finally:
            self.audit.append(entry)
