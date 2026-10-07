"""Google Kubernetes Engine: same reads as the Kubernetes connector, but it
connects with a Google service account instead of a kubeconfig.

Setup (read-only):
    gcloud iam service-accounts create incident-agent --project <project>
    gcloud projects add-iam-policy-binding <project> \\
        --member serviceAccount:incident-agent@<project>.iam.gserviceaccount.com \\
        --role roles/container.viewer
Then paste a key JSON for that account, or leave it empty when the agent
runs on GCP with Workload Identity (application default credentials).
"""

import base64
import json
import tempfile

from .base import ConnectorError
from .kubernetes import NOTES, Kubernetes

SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]


class GKE(Kubernetes):
    type = "gke"
    LABEL = "Google Kubernetes Engine (GKE)"
    FIELDS = [
        {"key": "project", "label": "GCP project ID", "type": "text", "required": True},
        {"key": "location", "label": "Location", "type": "text", "required": True,
         "help": "Region or zone of the cluster, e.g. europe-west1"},
        {"key": "cluster", "label": "Cluster name", "type": "text", "required": True},
        {"key": "use_private_endpoint", "label": "Use private endpoint", "type": "bool", "default": False},
        {"key": "namespaces", "label": "Namespaces", "type": "list", "required": True},
        {"key": "label_selector", "label": "Label selector", "type": "text", "default": "app={service}"},
        {"key": "namespace_map", "label": "Service → namespace map (JSON)", "type": "json", "default": {},
         "help": 'Optional. Default: the namespace named like the service, else the allowed namespace that '
                 'has its deployment. e.g. {"checkout": "shop"}'},
    ]
    DEFAULT_NOTES = NOTES.format(what="Kubernetes on GKE (read-only).")
    SECRETS = [{"key": "service_account_json", "label": "Service account key (JSON)", "required": False,
                "multiline": True,
                "help": "Account with roles/container.viewer. Leave empty to use Workload Identity / default credentials."}]

    def credentials(self):
        import google.auth
        from google.auth.transport.requests import Request
        from google.oauth2 import service_account

        raw = self.secret("service_account_json", required=False)
        try:
            if raw:
                creds = service_account.Credentials.from_service_account_info(json.loads(raw), scopes=SCOPES)
            else:
                creds, _ = google.auth.default(scopes=SCOPES)
            creds.refresh(Request())
        except (ValueError, KeyError) as e:
            raise ConnectorError(f"gke: invalid service account key: {e}") from e
        except Exception as e:
            raise ConnectorError(f"gke: cannot get Google credentials: {e}") from e
        return creds

    def cluster_info(self, token: str) -> dict:
        import requests

        url = (f"https://container.googleapis.com/v1/projects/{self.setting('project')}"
               f"/locations/{self.setting('location')}/clusters/{self.setting('cluster')}")
        r = requests.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=15)
        if r.status_code in (401, 403):
            raise ConnectorError(f"gke: access denied to cluster ({r.status_code}); grant roles/container.viewer")
        if r.status_code == 404:
            raise ConnectorError("gke: cluster not found — check project, location and cluster name")
        r.raise_for_status()
        return r.json()

    def clients(self):
        if self.api is None:
            from kubernetes import client

            creds = self.credentials()
            info = self.cluster_info(creds.token)
            endpoint = info["endpoint"]
            if self.settings.get("use_private_endpoint"):
                endpoint = info.get("privateClusterConfig", {}).get("privateEndpoint") or endpoint
            ca = tempfile.NamedTemporaryFile(prefix="gke-ca-", suffix=".crt", delete=False)
            ca.write(base64.b64decode(info["masterAuth"]["clusterCaCertificate"]))
            ca.close()
            cfg = client.Configuration()
            cfg.host = f"https://{endpoint}"
            cfg.ssl_ca_cert = ca.name
            cfg.api_key = {"authorization": f"Bearer {creds.token}"}
            api_client = client.ApiClient(cfg)
            self.api = self._make_api(api_client)
        return self.api

    def native_query(self, capability, args):
        cluster = f"{self.settings.get('project')}/{self.settings.get('location')}/{self.settings.get('cluster')}"
        return f"[gke {cluster}] " + super().native_query(capability, args)
