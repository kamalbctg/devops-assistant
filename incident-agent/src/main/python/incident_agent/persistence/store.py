"""Database for connectors, agents and investigations.

SQLite by default (DATA_DIR/incident-agent.db); Postgres when DATABASE_URL
is set. Uses SQLAlchemy Core so the same code works on both.
"""

import os
import threading
import time
import uuid
from pathlib import Path

import sqlalchemy as sa

meta = sa.MetaData()

connectors = sa.Table(
    "connectors", meta,
    sa.Column("id", sa.String(32), primary_key=True),
    sa.Column("name", sa.String(200), nullable=False, unique=True),
    sa.Column("type", sa.String(50), nullable=False),
    sa.Column("mode", sa.String(10), nullable=False, default="live"),
    sa.Column("provides", sa.JSON, nullable=False),
    sa.Column("settings", sa.JSON, nullable=False),
    sa.Column("secrets", sa.Text),  # encrypted
    sa.Column("notes", sa.Text),  # how the agent should use this source; NULL = type default
    sa.Column("status", sa.String(20), nullable=False, default="untested"),  # untested | ok | failed
    sa.Column("status_detail", sa.Text),
    sa.Column("tested_at", sa.Float),
    sa.Column("created_at", sa.Float, nullable=False),
    sa.Column("updated_at", sa.Float, nullable=False),
)

agents = sa.Table(
    "agents", meta,
    sa.Column("id", sa.String(32), primary_key=True),
    sa.Column("name", sa.String(200), nullable=False, unique=True),
    sa.Column("type", sa.String(50), nullable=False, default="incident_investigation"),
    sa.Column("description", sa.Text),
    sa.Column("services", sa.JSON, nullable=False),
    sa.Column("connector_ids", sa.JSON, nullable=False),  # order = priority
    sa.Column("budget", sa.JSON, nullable=False),
    sa.Column("timezone", sa.String(64), nullable=False, default="UTC"),
    sa.Column("llm", sa.JSON),  # {"model", "fast_model", "effort"}; NULL = defaults
    sa.Column("prompt", sa.Text),  # agent instructions, stored for every agent
    sa.Column("analysis_fields", sa.JSON),  # post-investigation analysis field definitions; NULL = none
    sa.Column("created_at", sa.Float, nullable=False),
    sa.Column("updated_at", sa.Float, nullable=False),
)

settings = sa.Table(
    "settings", meta,
    sa.Column("id", sa.String(50), primary_key=True),  # e.g. "llm"
    sa.Column("value", sa.JSON, nullable=False),
    sa.Column("secrets", sa.Text),  # encrypted
    sa.Column("updated_at", sa.Float, nullable=False),
)

investigations = sa.Table(
    "investigations", meta,
    sa.Column("id", sa.String(32), primary_key=True),
    sa.Column("agent_id", sa.String(32), nullable=False),
    sa.Column("agent_name", sa.String(200)),
    sa.Column("question", sa.Text, nullable=False),
    sa.Column("source", sa.String(30), nullable=False),
    sa.Column("status", sa.String(20), nullable=False),
    sa.Column("created", sa.Float, nullable=False),
    sa.Column("dedup_key", sa.String(300)),
    sa.Column("data", sa.JSON, nullable=False),  # events, interrupt, report, verdict, result, error, audit
)


def database_url(data_dir: str | Path) -> str:
    url = os.environ.get("DATABASE_URL")
    if url:
        return url.replace("postgresql://", "postgresql+psycopg://", 1).replace("postgres://", "postgresql+psycopg://", 1)
    Path(data_dir).mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{Path(data_dir) / 'incident-agent.db'}"


def new_id() -> str:
    return uuid.uuid4().hex[:12]


class Store:
    def __init__(self, url: str):
        kw = {"connect_args": {"check_same_thread": False}} if url.startswith("sqlite") else {"pool_pre_ping": True}
        self.engine = sa.create_engine(url, **kw)
        meta.create_all(self.engine)
        self._migrate()
        self.lock = threading.Lock()

    def _migrate(self):
        """Tiny forward-only migrations for databases created by older versions."""
        ccols = {c["name"] for c in sa.inspect(self.engine).get_columns("connectors")}
        if "notes" not in ccols:
            with self.engine.begin() as c:
                c.execute(sa.text("ALTER TABLE connectors ADD COLUMN notes TEXT"))
        cols = {c["name"] for c in sa.inspect(self.engine).get_columns("agents")}
        if "type" not in cols:
            with self.engine.begin() as c:
                c.execute(sa.text("ALTER TABLE agents ADD COLUMN type VARCHAR(50) NOT NULL DEFAULT 'incident_investigation'"))
        if "analysis_fields" not in cols:
            with self.engine.begin() as c:
                c.execute(sa.text("ALTER TABLE agents ADD COLUMN analysis_fields JSON"))
        if "prompt" not in cols:
            with self.engine.begin() as c:
                c.execute(sa.text("ALTER TABLE agents ADD COLUMN prompt TEXT"))
        with self.engine.begin() as c:  # agents saved before prompts were always stored: store the default
            from incident_agent.agent.prompts import DEFAULT_INSTRUCTIONS
            c.execute(agents.update().where(agents.c.prompt.is_(None)).values(prompt=DEFAULT_INSTRUCTIONS.strip()))
        if "llm" not in cols:
            with self.engine.begin() as c:
                c.execute(sa.text("ALTER TABLE agents ADD COLUMN llm JSON"))
                # agents created before this column ran without an LLM: keep that until edited
                c.execute(agents.update().values(llm={"model": "scripted", "fast_model": "claude-haiku-4-5", "effort": "medium"}))

    # ---- generic helpers ----

    def _all(self, table, order=None, where=None, limit=None):
        q = sa.select(table)
        if where is not None:
            q = q.where(where)
        if order is not None:
            q = q.order_by(order)
        if limit:
            q = q.limit(limit)
        with self.engine.connect() as c:
            return [dict(r._mapping) for r in c.execute(q)]

    def _one(self, table, id_):
        rows = self._all(table, where=table.c.id == id_)
        return rows[0] if rows else None

    def _insert(self, table, values):
        with self.engine.begin() as c:
            c.execute(table.insert().values(**values))
        return values

    def _update(self, table, id_, values):
        with self.engine.begin() as c:
            return c.execute(table.update().where(table.c.id == id_).values(**values)).rowcount

    def _delete(self, table, id_):
        with self.engine.begin() as c:
            return c.execute(table.delete().where(table.c.id == id_)).rowcount

    # ---- connectors ----

    def list_connectors(self):
        return self._all(connectors, order=connectors.c.name)

    def get_connector(self, id_):
        return self._one(connectors, id_)

    def create_connector(self, values: dict):
        now = time.time()
        return self._insert(connectors, {"id": new_id(), "status": "untested", "created_at": now, "updated_at": now, **values})

    def update_connector(self, id_, values: dict):
        return self._update(connectors, id_, {**values, "updated_at": time.time()})

    def delete_connector(self, id_):
        return self._delete(connectors, id_)

    # ---- agents ----

    def list_agents(self):
        return self._all(agents, order=agents.c.name)

    def get_agent(self, id_):
        return self._one(agents, id_)

    def create_agent(self, values: dict):
        now = time.time()
        return self._insert(agents, {"id": new_id(), "created_at": now, "updated_at": now, **values})

    def update_agent(self, id_, values: dict):
        return self._update(agents, id_, {**values, "updated_at": time.time()})

    def delete_agent(self, id_):
        return self._delete(agents, id_)

    def agents_using(self, connector_id):
        return [a for a in self.list_agents() if connector_id in a["connector_ids"]]

    # ---- settings ----

    def get_setting(self, id_):
        return self._one(settings, id_)

    def put_setting(self, id_, value: dict, secrets: str | None):
        row = {"id": id_, "value": value, "secrets": secrets, "updated_at": time.time()}
        with self.lock:
            if not self._update(settings, id_, row):
                self._insert(settings, row)

    # ---- investigations ----

    def save_investigation(self, row: dict):
        with self.lock:
            if not self._update(investigations, row["id"], row):
                self._insert(investigations, row)

    def get_investigation(self, id_):
        return self._one(investigations, id_)

    def list_investigations(self, limit=100, agent_id: str | None = None):
        where = investigations.c.agent_id == agent_id if agent_id else None
        return self._all(investigations, order=investigations.c.created.desc(), where=where, limit=limit)

    def recent_by_dedup(self, key: str, since: float):
        return self._all(investigations, where=sa.and_(investigations.c.dedup_key == key,
                                                       investigations.c.created >= since,
                                                       investigations.c.status != "failed"))
