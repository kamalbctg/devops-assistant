"""Database for connectors, agents and investigations.

SQLite by default (DATA_DIR/incident-agent.db); Postgres when DATABASE_URL
is set. Uses SQLAlchemy Core so the same code works on both. The tables below are
the target schema; Alembic migrations (persistence/migrations) bring a database to it.
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
    sa.Column("connector_ids", sa.JSON, nullable=False),  # display order only: all connectors are equal
    sa.Column("budget", sa.JSON, nullable=False),
    sa.Column("timezone", sa.String(64), nullable=False, default="UTC"),
    sa.Column("llm", sa.JSON),  # {"model", "fast_model", "effort"}; NULL = defaults
    sa.Column("prompt", sa.Text),  # agent instructions, stored for every agent (= the text of prompt_version)
    sa.Column("prompt_version", sa.Integer),  # the saved version in use; may be older than the newest one
    sa.Column("analysis_fields", sa.JSON),  # post-investigation analysis field definitions; NULL = none
    sa.Column("retention", sa.JSON),  # {"keep_days", "max_investigations"}; NULL = the maximum (7 days, 100)
    sa.Column("created_at", sa.Float, nullable=False),
    sa.Column("updated_at", sa.Float, nullable=False),
)

# Every saved change of an agent's instructions; investigations record which version they ran with.
# agents.prompt_version points at the one in use: switching back to an old version does not copy it.
prompt_versions = sa.Table(
    "prompt_versions", meta,
    sa.Column("agent_id", sa.String(32), primary_key=True),
    sa.Column("version", sa.Integer, primary_key=True),  # 1, 2, 3 ... per agent
    sa.Column("prompt", sa.Text, nullable=False),
    sa.Column("note", sa.String(300)),  # e.g. "restored from v2"
    sa.Column("created_at", sa.Float, nullable=False),
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
        from incident_agent.persistence.schema import upgrade

        upgrade(self.engine)
        self.lock = threading.Lock()

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

    def create_agent(self, values: dict, prompt_note: str | None = "created"):
        now = time.time()
        row = self._insert(agents, {"id": new_id(), "created_at": now, "updated_at": now, **values})
        if values.get("prompt"):
            self.save_prompt_version(row["id"], values["prompt"], prompt_note)
        return row

    def update_agent(self, id_, values: dict, prompt_note: str | None = None):
        n = self._update(agents, id_, {**values, "updated_at": time.time()})
        if n and values.get("prompt"):
            self.save_prompt_version(id_, values["prompt"], prompt_note)
        return n

    def delete_agent(self, id_):
        with self.engine.begin() as c:
            c.execute(prompt_versions.delete().where(prompt_versions.c.agent_id == id_))
        return self._delete(agents, id_)

    # ---- prompt versions ----

    def save_prompt_version(self, agent_id: str, prompt: str, note: str | None = None) -> int:
        """Record the agent's instructions as a new version if they differ from the one in use,
        and make it the one in use. Returns the version in use."""
        with self.lock, self.engine.begin() as c:
            active = c.execute(sa.select(agents.c.prompt_version).where(agents.c.id == agent_id)).scalar()
            cur = c.execute(sa.select(prompt_versions.c.prompt).where(
                prompt_versions.c.agent_id == agent_id, prompt_versions.c.version == active)).scalar() if active else None
            if cur == prompt:
                return active
            last = c.execute(sa.select(sa.func.max(prompt_versions.c.version))
                             .where(prompt_versions.c.agent_id == agent_id)).scalar() or 0
            c.execute(prompt_versions.insert().values(agent_id=agent_id, version=last + 1, prompt=prompt,
                                                      note=(note or "").strip()[:300] or None, created_at=time.time()))
            c.execute(agents.update().where(agents.c.id == agent_id).values(prompt_version=last + 1))
            return last + 1

    def activate_prompt_version(self, agent_id: str, version: int) -> bool:
        """Switch the agent to an existing saved version, without copying it. False if it does not exist."""
        row = self.prompt_version(agent_id, version)
        if row is None:
            return False
        self._update(agents, agent_id, {"prompt": row["prompt"], "prompt_version": version, "updated_at": time.time()})
        return True

    def prompt_versions(self, agent_id: str) -> list[dict]:
        """Newest first, with the text."""
        return self._all(prompt_versions, order=prompt_versions.c.version.desc(),
                         where=prompt_versions.c.agent_id == agent_id)

    def prompt_version(self, agent_id: str, version: int | None = None) -> dict | None:
        """One version, or the one in use when `version` is None (the newest if none is marked)."""
        if version is None:
            agent = self.get_agent(agent_id)
            version = agent.get("prompt_version") if agent else None
        where = prompt_versions.c.agent_id == agent_id
        if version is not None:
            where = sa.and_(where, prompt_versions.c.version == version)
        rows = self._all(prompt_versions, order=prompt_versions.c.version.desc(), where=where, limit=1)
        return rows[0] if rows else None

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

    def count_investigations(self, agent_id: str) -> int:
        q = sa.select(sa.func.count()).select_from(investigations).where(investigations.c.agent_id == agent_id)
        with self.engine.connect() as c:
            return c.execute(q).scalar_one()

    def finished_before(self, cutoff: float) -> list[dict]:
        """id, agent_id, created of investigations started before `cutoff` that are not running."""
        q = (sa.select(investigations.c.id, investigations.c.agent_id, investigations.c.created)
             .where(investigations.c.created < cutoff, investigations.c.status != "running"))
        with self.engine.connect() as c:
            return [dict(r._mapping) for r in c.execute(q)]

    def delete_investigation(self, id_):
        return self._delete(investigations, id_)

    def get_investigation(self, id_):
        return self._one(investigations, id_)

    def list_investigations(self, limit=100, agent_id: str | None = None, status: str | None = None):
        conds = []
        if agent_id:
            conds.append(investigations.c.agent_id == agent_id)
        if status:
            conds.append(investigations.c.status == status)
        where = sa.and_(*conds) if conds else None
        return self._all(investigations, order=investigations.c.created.desc(), where=where, limit=limit)

    def recent_by_dedup(self, key: str, since: float):
        return self._all(investigations, where=sa.and_(investigations.c.dedup_key == key,
                                                       investigations.c.created >= since,
                                                       investigations.c.status != "failed"))
