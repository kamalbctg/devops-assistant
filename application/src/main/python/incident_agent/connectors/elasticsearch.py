"""Elasticsearch / OpenSearch-compatible log search.

settings:
    url: https://es.example.com:9200
    api_key_env: env var with an API key bound to a read-only role
    indices: ["app-logs-*"]          — '*' alone and system indices are rejected
    service_field: service.name
    message_field: message           (full-text match)
    message_keyword_field: message.keyword   (top messages aggregation)
"""

import json
import re

from .base import Connector, ConnectorError

# the level words each `level` keeps; without a level field these are matched in the message text
LEVEL_WORDS = {"error": ["ERROR", "FATAL", "CRITICAL", "SEVERE"],
               "warn": ["WARN", "WARNING", "ERROR", "FATAL", "CRITICAL", "SEVERE"]}


def es_query(q: str) -> str:
    """The model's query (Datadog-like: a OR b, AND, NOT) in simple_query_string syntax."""
    q = re.sub(r"\s+OR\s+", " | ", q.strip())
    q = re.sub(r"\s+AND\s+", " + ", q)
    return re.sub(r"(^|\s)NOT\s+", r"\1-", q)


class Elasticsearch(Connector):
    type = "elasticsearch"
    capabilities = {"logs.search"}
    LABEL = "Elasticsearch"
    FIELDS = [
        {"key": "url", "label": "URL", "type": "text", "required": True, "help": "https://es.example.com:9200"},
        {"key": "indices", "label": "Index patterns", "type": "list", "required": True, "default": ["app-logs-*"],
         "help": "Comma separated. '*' and system indices are not allowed."},
        {"key": "service_field", "label": "Service field", "type": "text", "default": "service.name"},
        {"key": "message_field", "label": "Message field", "type": "text", "default": "message"},
        {"key": "message_keyword_field", "label": "Message keyword field", "type": "text",
         "help": "Keyword copy of the message for 'top messages' (e.g. message.keyword). "
                 "Leave empty when the message is plain text (e.g. log): example lines are shown instead."},
        {"key": "exclude_levels", "label": "Leave out log levels", "type": "list", "default": ["DEBUG", "TRACE"],
         "help": "Lines containing these words are not searched, so errors are not buried. Empty = search all."},
        {"key": "level_field", "label": "Level field", "type": "text",
         "help": "Field holding the log level (e.g. level, log.level), for the 'error'/'warn' filter. "
                 "Empty: the level is read from the message text (lines with INFO/DEBUG/TRACE are left out)."},
    ]
    DEFAULT_NOTES = """Application logs. logs_search matches `query` in the message field for the service
within the time window, and returns the hit count, first-seen time and top or example messages.
Query: all words must appear; 'a OR b' for either; "quotes" for an exact phrase. To find failures
set level=error (or warn) instead of searching for the word "error". Search for specific terms
(status codes like "502", exception names, request IDs, endpoints). Narrow since/until around the
spike: examples are the earliest matching lines. Zero hits usually means a wrong service name,
field or window."""
    SECRETS = [{"key": "api_key", "label": "API key", "required": True,
                "help": "Bound to a role with read + view_index_metadata on these indices only."}]
    client = None  # tests inject a stub

    def validate_settings(self):
        indices = self.settings.get("indices") or []
        if not indices:
            raise ConnectorError("elasticsearch: settings.indices is required")
        bad = [i for i in indices if i.strip() in ("*", "_all") or i.startswith(".")]
        if bad:
            raise ConnectorError(f"elasticsearch: index patterns not allowed: {bad}")

    def es(self):
        if self.client is None:
            from elasticsearch import Elasticsearch as ES

            self.client = ES(self.setting("url"), api_key=self.secret("api_key"),
                             request_timeout=self.settings.get("timeout_s", 15))
        return self.client

    def _index(self):
        return ",".join(self.settings["indices"])

    def body(self, args):
        start, end = self.window(args) if self.mode == "live" else (None, None)
        # match_phrase works whether the service field is keyword or text (e.g. kubernetes.container_name)
        must = [{"match_phrase": {self.settings.get("service_field", "service.name"): args["service"]}},
                {"range": {"@timestamp": {"gte": start.isoformat() if start else args["since"],
                                          **({"lte": end.isoformat()} if end else {})}}}]
        mf = self.settings.get("message_field", "message")
        if args.get("query"):
            must.append({"simple_query_string": {"query": es_query(args["query"]), "fields": [mf],
                                                 "default_operator": "and"}})
        lvl, level_field = args.get("level"), self.settings.get("level_field")
        if lvl and level_field:
            words = LEVEL_WORDS[lvl]
            must.append({"terms": {level_field: words + [w.lower() for w in words]}})
        elif lvl:  # level only in the text: keep lines with a level word, drop the quieter ones
            must.append({"simple_query_string": {"query": " | ".join(LEVEL_WORDS[lvl] + ["Exception"]),
                                                 "fields": [mf]}})
        kw = self.settings.get("message_keyword_field")
        top = ({"terms": {"field": kw, "size": 3}} if kw else
               {"top_hits": {"size": 3, "sort": [{"@timestamp": "asc"}],
                             "_source": [self.settings.get("message_field", "message")]}})
        # debug/trace lines bury the errors; leave them out unless the connector says otherwise
        skip = list(self.settings.get("exclude_levels", ["DEBUG", "TRACE"]))
        if lvl and not level_field:
            skip += [w for w in ("INFO", "DEBUG", "TRACE") + (("WARN",) if lvl == "error" else ()) if w not in skip]
        must_not = [{"match_phrase": {mf: w}} for w in skip]
        return {"query": {"bool": {"filter": must, **({"must_not": must_not} if must_not else {})}},
                "aggs": {"first_seen": {"min": {"field": "@timestamp"}}, "top": top}}

    def native_query(self, capability, args):
        return f"GET {self._index()}/_search " + json.dumps({"size": 0, **self.body(args)})

    def read_probe(self):
        self.es().count(index=self._index())

    def write_probe(self):
        """has_privileges asks the cluster what this key may do. Nothing is written."""
        try:
            r = self.es().security.has_privileges(
                index=[{"names": self.settings["indices"], "privileges": ["write", "index", "delete", "manage"]}])
        except Exception as e:
            raise ConnectorError(f"elasticsearch: cannot verify read-only access ({e}); is security enabled?") from e
        return any(any(p.values()) for p in r["index"].values())

    def discover_services(self):
        field = self.settings.get("service_field", "service.name")
        for f in (field, f"{field}.keyword"):  # text fields aggregate via their .keyword copy
            try:
                r = self.es().search(index=self._index(), size=0, query={"range": {"@timestamp": {"gte": "now-24h"}}},
                                     aggs={"s": {"terms": {"field": f, "size": 200}}})
            except Exception:
                continue
            names = [b["key"] for b in r.get("aggregations", {}).get("s", {}).get("buckets", [])]
            if names:
                return names
        return []

    def fetch(self, capability, args):
        r = self.es().search(index=self._index(), size=0, track_total_hits=True, **self.body(args))
        aggs = r.get("aggregations", {})
        first = aggs.get("first_seen", {}).get("value_as_string")
        top = aggs.get("top", {})
        if "buckets" in top:
            rows = [[b["key"], b["doc_count"]] for b in top["buckets"]]
        else:  # top_hits: example lines, no counts
            mf = self.settings.get("message_field", "message")
            rows = []
            for h in top.get("hits", {}).get("hits", []):
                v = h.get("_source", {})
                for part in mf.split("."):
                    v = v.get(part, {}) if isinstance(v, dict) else {}
                rows.append([str(v)[:300], None])
        return {"total": r["hits"]["total"]["value"], "first_seen": self.hhmm(first, seconds=True), "top": rows}
