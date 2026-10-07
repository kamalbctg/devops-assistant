"""Alertmanager v2 API.

settings:
    url: http://alertmanager:9093
    token_env: optional bearer token env var
    service_label: alert label holding the service (default "service")
Alertmanager has no RBAC. Put it behind a proxy that only allows GET, or the
write probe fails and the connector is refused.
"""

from .base import ConnectorError
from .http import HttpConnector


class Alertmanager(HttpConnector):
    type = "alertmanager"
    supported = {"alerts.list"}
    LABEL = "Alertmanager"
    FIELDS = [
        {"key": "url", "label": "URL", "type": "text", "required": True,
         "help": "Use a proxy that only allows GET; Alertmanager has no access control."},
        {"key": "service_label", "label": "Service label", "type": "text", "default": "service"},
    ]
    DEFAULT_NOTES = """Active Prometheus alerts from Alertmanager for the service label: alert name, state
and start time. Silenced and inhibited alerts are excluded."""
    SECRETS = [{"key": "token", "label": "Bearer token (optional)", "required": False}]

    def _filter(self, args):
        return f'{self.settings.get("service_label", "service")}="{args["service"]}"'

    def native_query(self, capability, args):
        return f"GET /api/v2/alerts?filter={self._filter(args)}&active=true&silenced=false"

    def read_probe(self):
        self.get("/api/v2/status")

    def write_probe(self):
        """Empty silence body: rejected as invalid (400) if writes reach Alertmanager. Creates nothing."""
        with self.http() as c:
            r = c.post("/api/v2/silences", json={})
        if r.status_code in (401, 403, 405):
            return False
        if r.status_code >= 500:
            raise ConnectorError(f"alertmanager: write probe got {r.status_code}")
        return True

    def fetch(self, capability, args):
        alerts = self.get("/api/v2/alerts", filter=self._filter(args), active="true",
                          silenced="false", inhibited="false").json()
        return {"alerts": [{"name": a["labels"].get("alertname", "?"), "status": a["status"]["state"],
                            "since": self.hhmm(a.get("startsAt"))} for a in alerts]}
