"""ClickHouse with the OpenTelemetry exporter schema (otel_logs / otel_traces).

settings:
    host, port (8443), secure (true), username, database
    password_env: env var holding the password
    logs_table: otel_logs     traces_table: otel_traces
The ClickHouse user must have readonly=1 (checked by the write probe) and
SELECT only on the configured tables.
"""

import re

from .base import Connector, ConnectorError

LIMITS = {"max_execution_time": 10, "max_result_rows": 1000, "result_overflow_mode": "break"}
IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?$")


class ClickHouse(Connector):
    type = "clickhouse"
    capabilities = {"logs.search", "traces.search"}
    LABEL = "ClickHouse (OpenTelemetry)"
    FIELDS = [
        {"key": "host", "label": "Host", "type": "text", "required": True},
        {"key": "port", "label": "Port", "type": "number", "default": 8443},
        {"key": "secure", "label": "TLS", "type": "bool", "default": True},
        {"key": "username", "label": "Username", "type": "text", "required": True, "help": "User with readonly = 1"},
        {"key": "database", "label": "Database", "type": "text", "default": "default"},
        {"key": "logs_table", "label": "Logs table", "type": "text", "default": "otel_logs"},
        {"key": "traces_table", "label": "Traces table", "type": "text", "default": "otel_traces"},
    ]
    DEFAULT_NOTES = """OpenTelemetry data in ClickHouse. logs_search matches `query` in the log Body or
severity for ServiceName; traces_search returns span count, p99, error count, slowest span names and
database span p99. Trace IDs are the OTel trace IDs."""
    SECRETS = [{"key": "password", "label": "Password", "required": True}]
    client = None  # tests inject a stub

    def validate_settings(self):
        for key in ("logs_table", "traces_table"):
            if key in self.settings and not IDENT.match(self.settings[key]):
                raise ConnectorError(f"clickhouse: invalid table name {self.settings[key]!r}")

    def ch(self):
        if self.client is None:
            import clickhouse_connect

            self.client = clickhouse_connect.get_client(
                host=self.setting("host"), port=self.settings.get("port", 8443),
                secure=self.settings.get("secure", True), username=self.setting("username"),
                password=self.secret("password"), database=self.settings.get("database", "default"))
        return self.client

    def _where(self, args, logs: bool):
        where = "ServiceName = {service:String} AND Timestamp >= {start:DateTime64(9)} AND Timestamp <= {end:DateTime64(9)}"
        if logs and args.get("query"):
            where += " AND (Body ILIKE {pattern:String} OR SeverityText = upper({query:String}))"
        return where

    def _params(self, args):
        start, end = self.window(args) if self.mode == "live" else (args["since"], "now")
        q = args.get("query") or ""
        return {"service": args["service"], "start": start, "end": end, "pattern": f"%{q}%", "query": q}

    def sql(self, capability, args) -> dict[str, str]:
        logs, traces = self.settings.get("logs_table", "otel_logs"), self.settings.get("traces_table", "otel_traces")
        if capability == "logs.search":
            w = self._where(args, logs=True)
            return {
                "summary": f"SELECT count(), min(Timestamp) FROM {logs} WHERE {w}",
                "top": f"SELECT substring(Body, 1, 160) AS msg, count() AS c FROM {logs} WHERE {w} GROUP BY msg ORDER BY c DESC LIMIT 3",
            }
        w = self._where(args, logs=False)
        return {
            "summary": f"SELECT count(), quantile(0.99)(Duration) / 1e6, countIf(StatusCode IN ('Error', 'STATUS_CODE_ERROR')) FROM {traces} WHERE {w}",
            "ops": f"SELECT SpanName, quantile(0.99)(Duration) / 1e6 AS p FROM {traces} WHERE {w} GROUP BY SpanName ORDER BY p DESC LIMIT 3",
            "db": f"SELECT quantile(0.99)(Duration) / 1e6 FROM {traces} WHERE {w} AND SpanAttributes['db.system'] != ''",
        }

    def native_query(self, capability, args):
        return " ; ".join(self.sql(capability, args).values()) + f"  -- service={args['service']} since={args['since']}"

    def read_probe(self):
        self.ch().query("SELECT 1")

    def write_probe(self):
        """readonly=0 means this user could INSERT/ALTER. Checking the setting writes nothing."""
        rows = self.ch().query("SELECT value FROM system.settings WHERE name = 'readonly'").result_rows
        return not rows or str(rows[0][0]) == "0"

    def _q(self, sql, args):
        return self.ch().query(sql, parameters=self._params(args), settings=LIMITS).result_rows

    def discover_services(self):
        table = self.settings.get("logs_table", "otel_logs")
        rows = self.ch().query(f"SELECT DISTINCT ServiceName FROM {table} WHERE Timestamp > now() - INTERVAL 1 DAY LIMIT 500",
                               settings=LIMITS).result_rows
        return [r[0] for r in rows]

    def fetch(self, capability, args):
        sql = self.sql(capability, args)
        if capability == "logs.search":
            total, first = self._q(sql["summary"], args)[0]
            return {"total": int(total), "first_seen": self.hhmm(first, seconds=True) if total else None,
                    "top": [[m, int(c)] for m, c in self._q(sql["top"], args)]}
        count, p99, errors = self._q(sql["summary"], args)[0]
        db = self._q(sql["db"], args)
        nan = lambda v: None if v is None or v != v else round(float(v), 1)  # noqa: E731 — quantile of nothing is NaN
        return {"count": int(count), "p99_ms": nan(p99), "error_count": int(errors),
                "slowest_ops": [[n, nan(p)] for n, p in self._q(sql["ops"], args)],
                "db_p99_ms": nan(db[0][0]) if db else None}
