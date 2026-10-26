"""Kubernetes: pod health, pod logs, rollout history (ReplicaSets) and events.

settings:
    context: kubeconfig context (omit inside the cluster)
    namespaces: [checkout, payment]     — allowlist
    namespace_map: {checkout: shop}      — service → namespace (default: a namespace named like the
                                           service, else the allowed namespace whose deployment matches)
    label_selector: "app={service}"
The service account / user must have get/list/watch only (checked by the write probe):
pods, pods/log, events, deployments, replicasets, horizontalpodautoscalers.

Finding a service's deployment: the label selector first, then the deployment name — exact, or with an
environment prefix ("stage-<service>"). Deployment and pod lists are cached for 30 s per namespace, so
sweeping many services costs one list call per namespace.
"""

import json
import re
import time
from collections import Counter
from datetime import datetime

from .base import Connector, ConnectorError

CACHE_SECONDS = 30
MAX_LOG_PODS = 5          # pods read per log search (unhealthy ones first)
MAX_LOG_LINES = 5000      # tail per pod
BAD_WAITING = {"CrashLoopBackOff", "ImagePullBackOff", "ErrImagePull", "CreateContainerConfigError",
               "CreateContainerError", "InvalidImageName", "RunContainerError"}

NOTES = """{what}
- k8s_pods: pod health now — ready/total, restarts, last exit reason + exit code + time per pod,
  waiting reasons (CrashLoopBackOff, ImagePullBackOff), deployment replicas and failing conditions, HPA.
  Exit codes: 137 = OOMKilled / SIGKILL (memory limit), 143 = SIGTERM (graceful stop: rollout, scale-down,
  eviction — usually not a crash), 1 = application error (read the previous container's logs), 0 = completed.
- logs_search: pod logs straight from Kubernetes (all matching pods, unhealthy first; after a restart the
  previous container's last lines too — that is where a crash's cause is). Query: text, case-insensitive;
  'a OR b' for either. Empty query = all lines. level=error (or warn) keeps only lines with that level
  word or an exception, so search the error itself instead of the word "error".
- deploys_list: rollouts (image tag, time, previous tag) in the window, plus the version running now.
- k8s_events: events for the deployment, its ReplicaSets and pods (OOMKilled, BackOff, Killing, Unhealthy,
  FailedScheduling, FailedMount, Evicted) with counts and first time. Events are kept ~1 hour by the cluster.
Typical order: k8s_pods → k8s_events → logs_search for the error/exit you found → deploys_list for what changed.
A restart after a rollout with exit 143 is expected; exit 137/OOMKilled or exit 1 with repeating restarts is not."""


def _labels(selector: str) -> dict:
    return dict(part.split("=", 1) for part in selector.split(",") if "=" in part)


def _has(labels: dict | None, want: dict) -> bool:
    return bool(want) and all((labels or {}).get(k) == v for k, v in want.items())


_TS_FRACTION = re.compile(r"(\.\d{6})\d+")
# level=error / warn: a level word in the line (Java/Python/Go formats) or an exception name
LOG_LEVEL = {"error": re.compile(r"\b(ERROR|FATAL|CRITICAL|SEVERE|PANIC)\b|Exception|Traceback"),
             "warn": re.compile(r"\b(WARN|WARNING|ERROR|FATAL|CRITICAL|SEVERE|PANIC)\b|Exception|Traceback")}
_NOISE = re.compile(r"[0-9a-f]{8}-[0-9a-f-]{27}|0x[0-9a-f]+|\d+", re.I)


def _parse_line(raw: str) -> tuple[datetime | None, str]:
    """'2026-10-07T03:40:16.123456789Z message' (kubectl logs --timestamps) → (time, message).
    JSON log lines are shown as 'LEVEL message'."""
    stamp, _, text = raw.partition(" ")
    try:
        ts = datetime.fromisoformat(_TS_FRACTION.sub(r"\1", stamp).replace("Z", "+00:00"))
    except ValueError:
        ts, text = None, raw
    if text.startswith("{"):
        try:
            obj = json.loads(text)
            msg = obj.get("message") or obj.get("msg") or obj.get("log")
            if msg:
                level = obj.get("level") or obj.get("severity") or ""
                text = f"{level} {msg}".strip()
        except ValueError:
            pass
    return ts, text


class Kubernetes(Connector):
    type = "kubernetes"
    capabilities = {"logs.search", "deploys.list", "k8s.events", "k8s.pods"}
    LABEL = "Kubernetes (kubeconfig)"
    DEFAULT_NOTES = NOTES.format(what="Kubernetes cluster (read-only).")
    FIELDS = [
        {"key": "context", "label": "kubeconfig context", "type": "text",
         "help": "Context to use from the pasted kubeconfig (empty = its current-context)."},
        {"key": "namespaces", "label": "Namespaces", "type": "list", "required": True},
        {"key": "label_selector", "label": "Label selector", "type": "text", "default": "app={service}"},
        {"key": "namespace_map", "label": "Service → namespace map (JSON)", "type": "json", "default": {},
         "help": 'Optional. Default: the namespace named like the service, else the allowed namespace that '
                 'has its deployment. e.g. {"checkout": "shop"}'},
    ]
    SECRETS = [{"key": "kubeconfig", "label": "kubeconfig (paste YAML)", "required": False, "multiline": True,
                "help": "Token or client-certificate kubeconfigs work anywhere. Exec-based ones (gke-gcloud-auth-plugin) "
                        "need gcloud on the server — use the GKE connector instead. Empty = in-cluster or the server's "
                        "~/.kube/config."}]
    api = None  # tests inject a stub: object with .apps, .core, .authz (and optionally .autoscaling)

    def _make_api(self, api_client=None):
        from types import SimpleNamespace

        from kubernetes import client

        args = (api_client,) if api_client is not None else ()
        return SimpleNamespace(apps=client.AppsV1Api(*args), core=client.CoreV1Api(*args),
                               authz=client.AuthorizationV1Api(*args), autoscaling=client.AutoscalingV2Api(*args),
                               models=client)

    def clients(self):
        if self.api is None:
            import yaml
            from kubernetes import config

            pasted = self.secret("kubeconfig", required=False)
            if pasted:
                try:
                    cfg = yaml.safe_load(pasted)
                    api_client = config.new_client_from_config_dict(cfg, context=self.settings.get("context") or None)
                except yaml.YAMLError as e:  # its message quotes the bad line, which may hold the token
                    mark = getattr(e, "problem_mark", None)
                    where = f" at line {mark.line + 1}" if mark else ""
                    raise ConnectorError(f"{self.type}: invalid kubeconfig: not valid YAML{where}") from e
                except Exception as e:
                    raise ConnectorError(f"{self.type}: invalid kubeconfig: {type(e).__name__}: {e}") from e
                self.api = self._make_api(api_client)
                return self.api
            try:
                config.load_incluster_config()
            except config.ConfigException:
                config.load_kube_config(context=self.settings.get("context"))
            self.api = self._make_api()
        return self.api

    # ------------------------------------------------------------ lookups (cached per namespace)

    def _cached(self, key, load):
        cache = self.__dict__.setdefault("_cache", {})
        hit = cache.get(key)
        if hit and time.monotonic() - hit[0] < CACHE_SECONDS:
            return hit[1]
        value = load()
        cache[key] = (time.monotonic(), value)
        return value

    def deployments(self, ns):
        return self._cached(("deployments", ns), lambda: self.clients().apps.list_namespaced_deployment(ns).items)

    def pods(self, ns):
        return self._cached(("pods", ns), lambda: self.clients().core.list_namespaced_pod(ns).items)

    def selector(self, service):
        return self.settings.get("label_selector", "app={service}").format(service=service)

    def _match(self, ns, service):
        """The deployment for a service in one namespace: by label selector, exact name, or 'env-<service>'."""
        deps = self.deployments(ns)
        want = _labels(self.selector(service))
        return (next((d for d in deps if _has(d.spec.template.metadata.labels, want)), None)
                or next((d for d in deps if d.metadata.name == service), None)
                or next((d for d in deps if d.metadata.name.endswith("-" + service)), None))

    def locate(self, service):
        """(namespace, deployment or None). namespace_map wins; else a namespace named like the service;
        else the first allowed namespace with a matching deployment."""
        allowed = self.settings.get("namespaces")
        ns = self.settings.get("namespace_map", {}).get(service)
        if ns is None and allowed and service not in allowed:
            for candidate in allowed:
                deployment = self._match(candidate, service)
                if deployment is not None:
                    return candidate, deployment
            raise ConnectorError(f"kubernetes: no deployment matching {service!r} in namespaces {allowed} "
                                 f"(and namespace {service!r} not in allowlist); set a service → namespace map "
                                 "or check the label selector")
        ns = ns or service
        if allowed and ns not in allowed:
            raise ConnectorError(f"kubernetes: namespace {ns!r} not in allowlist {allowed}")
        return ns, self._match(ns, service)

    def namespace(self, service):
        return self.locate(service)[0]

    def pod_selector(self, service, deployment) -> dict:
        if deployment is not None and deployment.spec.selector.match_labels:
            return dict(deployment.spec.selector.match_labels)
        return _labels(self.selector(service))

    def service_pods(self, ns, service, deployment):
        want = self.pod_selector(service, deployment)
        return [p for p in self.pods(ns) if _has(p.metadata.labels, want)]

    # ------------------------------------------------------------ connector interface

    def native_query(self, capability, args):
        s = args["service"]
        ns, name, sel = self.settings.get("namespace_map", {}).get(s, s), s, self.selector(s)
        if self.mode != "fake":
            try:
                ns, deployment = self.locate(s)
                name = deployment.metadata.name if deployment is not None else s
                sel = ",".join(f"{k}={v}" for k, v in self.pod_selector(s, deployment).items())
            except Exception:  # noqa: BLE001 — fetch reports the real error
                pass
        if capability == "deploys.list":
            return f"kubectl -n {ns} get replicasets -l {sel} (rollout history of deployment/{name})"
        if capability == "k8s.pods":
            return f"kubectl -n {ns} get pods -l {sel} -o wide; kubectl -n {ns} get deployment/{name} hpa"
        if capability == "logs.search":
            q = args.get("query") or ""
            lvl = f" | grep -E '{LOG_LEVEL[args['level']].pattern}'" if args.get("level") else ""
            return f"kubectl -n {ns} logs -l {sel} --timestamps --since=<window>" + (f" | grep -i '{q}'" if q else "") + lvl + \
                " (+ --previous for restarted pods)"
        return f"kubectl -n {ns} get events | grep {name}"

    def read_probe(self):
        ns = (self.settings.get("namespaces") or ["default"])[0]
        self.clients().core.list_namespaced_event(ns, limit=1)

    def write_probe(self):
        """SelfSubjectAccessReview: ask the API server 'may I?' — nothing is changed."""
        api = self.clients()
        m = api.models
        for ns in self.settings.get("namespaces") or ["default"]:
            for group, resource in (("apps", "deployments"), ("", "pods")):
                for verb in ("create", "patch", "delete"):
                    review = m.V1SelfSubjectAccessReview(spec=m.V1SelfSubjectAccessReviewSpec(
                        resource_attributes=m.V1ResourceAttributes(namespace=ns, verb=verb, group=group, resource=resource)))
                    if api.authz.create_self_subject_access_review(review).status.allowed:
                        return True
        return False

    def discover_services(self):
        names = set()
        for ns in self.settings.get("namespaces") or []:
            names |= {d.metadata.name for d in self.deployments(ns)}
        return list(names)

    def fetch(self, capability, args):
        s = args["service"]
        ns, deployment = self.locate(s)
        start, end = self.window(args)
        if capability == "deploys.list":
            return self._deploys(ns, s, deployment, start)
        if capability == "k8s.pods":
            return self._pods(ns, s, deployment, start)
        if capability == "logs.search":
            return self._logs(ns, s, deployment, start, end, args.get("query") or "", args.get("level"))
        return self._events(ns, s, deployment, start)

    # ------------------------------------------------------------ capabilities

    def _deploys(self, ns, service, deployment, start):
        sel = ",".join(f"{k}={v}" for k, v in self.pod_selector(service, deployment).items())
        rss = self.clients().apps.list_namespaced_replica_set(ns, label_selector=sel).items
        rss.sort(key=lambda r: int((r.metadata.annotations or {}).get("deployment.kubernetes.io/revision", 0)))
        versions = [(r.metadata.creation_timestamp, r.spec.template.spec.containers[0].image.rsplit(":", 1)[-1]) for r in rss]
        deploys = [{"version": v, "time": self.hhmm(t, seconds=True), "previous": versions[i - 1][1] if i else None}
                   for i, (t, v) in enumerate(versions) if t >= start]
        current = None
        if versions:
            t, v = versions[-1]
            current = {"version": v, "since": t.astimezone(self.tz).strftime("%Y-%m-%d %H:%M")}
        return {"deploys": deploys, "current": current}

    def _events(self, ns, service, deployment, start):
        name = deployment.metadata.name if deployment is not None else service
        events = []
        for e in self.clients().core.list_namespaced_event(ns).items:
            when = e.last_timestamp or e.event_time or e.metadata.creation_timestamp
            if e.involved_object.name.startswith(name) and when and when >= start:
                events.append((when, e.reason, getattr(e, "count", None) or 1))
        reasons = Counter()
        for _, reason, n in events:
            reasons[reason] += n
        return {"total": sum(reasons.values()), "first": self.hhmm(min(events)[0], seconds=True) if events else None,
                "reasons": dict(reasons)}

    def _pods(self, ns, service, deployment, start):
        rows, first_problem = [], None
        for p in self.service_pods(ns, service, deployment):
            cs = p.status.container_statuses or []
            waiting = next((c.state.waiting.reason for c in cs if c.state and c.state.waiting and c.state.waiting.reason), None)
            exits = [c.last_state.terminated for c in cs if c.last_state and c.last_state.terminated]
            last = max(exits, key=lambda t: t.finished_at or start, default=None)
            last_exit = None
            if last is not None:
                recent = bool(last.finished_at and last.finished_at >= start)
                at = (self.hhmm(last.finished_at, seconds=True) if recent or not last.finished_at
                      else last.finished_at.astimezone(self.tz).strftime("%Y-%m-%d %H:%M"))  # older: show the day
                last_exit = {"reason": last.reason, "exit_code": last.exit_code, "at": at, "recent": recent}
                if recent and (first_problem is None or last.finished_at < first_problem):
                    first_problem = last.finished_at
            rows.append({"pod": p.metadata.name, "phase": p.status.phase, "ready": bool(cs) and all(c.ready for c in cs),
                         "restarts": sum(c.restart_count for c in cs), "waiting": waiting, "last_exit": last_exit,
                         "node": p.spec.node_name})
        rows.sort(key=lambda r: (r["ready"], not (r["last_exit"] or {}).get("recent"), r["pod"]))  # unhealthy first

        dep = None
        if deployment is not None:
            st = deployment.status
            dep = {"name": deployment.metadata.name, "desired": deployment.spec.replicas or 0,
                   "ready": st.ready_replicas or 0, "available": st.available_replicas or 0,
                   "updated": st.updated_replicas or 0,
                   "problems": [f"{c.type}={c.status}" + (f" ({c.reason})" if c.reason else "")
                                for c in st.conditions or []
                                if c.status != "True" or c.reason == "ProgressDeadlineExceeded"]}
        return {"total": len(rows), "ready": sum(r["ready"] for r in rows), "restarts": sum(r["restarts"] for r in rows),
                "recent_restarts": sum(1 for r in rows if (r["last_exit"] or {}).get("recent")),
                "waiting": dict(Counter(r["waiting"] for r in rows if r["waiting"])),
                "pods": rows[:10], "deployment": dep, "hpa": self._hpa(ns, deployment),
                "first_problem": self.hhmm(first_problem, seconds=True)}

    def _hpa(self, ns, deployment):
        autoscaling = getattr(self.clients(), "autoscaling", None)
        if deployment is None or autoscaling is None:
            return None
        try:
            hpas = self._cached(("hpa", ns), lambda: autoscaling.list_namespaced_horizontal_pod_autoscaler(ns).items)
        except Exception:  # noqa: BLE001 — no permission for HPAs: just leave it out
            return None
        h = next((h for h in hpas if h.spec.scale_target_ref.name == deployment.metadata.name), None)
        if h is None:
            return None
        return {"min": h.spec.min_replicas, "max": h.spec.max_replicas,
                "current": h.status.current_replicas, "desired": h.status.desired_replicas}

    def _logs(self, ns, service, deployment, start, end, query, level=None):
        core = self.clients().core
        pods = self._pods(ns, service, deployment, start)["pods"][:MAX_LOG_PODS]  # unhealthy first
        terms = [t.strip().lower() for t in re.split(r"\s+OR\s+", query) if t.strip()]
        since_seconds = max(60, int((datetime.now(self.tz) - start).total_seconds()))
        container_name = deployment.spec.template.spec.containers[0].name if deployment is not None else None
        matches = []
        for p in pods:
            reads = [("", {"since_seconds": since_seconds, "tail_lines": MAX_LOG_LINES})]
            if (p["last_exit"] or {}).get("recent"):
                reads.append(("[previous container] ", {"previous": True, "tail_lines": 300}))
            for label, kw in reads:
                try:
                    text = core.read_namespaced_pod_log(p["pod"], ns, container=container_name, timestamps=True, **kw)
                except Exception:  # noqa: BLE001 — a pod gone or no previous container: skip that pod
                    continue
                for raw in (text or "").splitlines():
                    ts, msg = _parse_line(raw)
                    if ts is not None and not (start <= ts <= end) and not label:
                        continue
                    if terms and not any(t in raw.lower() for t in terms):
                        continue
                    if level and not LOG_LEVEL[level].search(raw):
                        continue
                    matches.append((ts, label + msg))
        groups, examples = Counter(), {}
        for _, msg in matches:
            key = _NOISE.sub("#", msg)[:200]
            groups[key] += 1
            examples.setdefault(key, msg)
        stamps = [ts for ts, _ in matches if ts is not None]
        return {"total": len(matches), "first_seen": self.hhmm(min(stamps), seconds=True) if stamps else None,
                "top": [[examples[k], n] for k, n in groups.most_common(3)], "pods_read": len(pods)}
