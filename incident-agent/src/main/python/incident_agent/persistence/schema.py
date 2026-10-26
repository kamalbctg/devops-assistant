"""Schema migrations with Alembic (revisions in persistence/migrations/versions).

The app upgrades the database to the newest revision on start. A database made before Alembic has
tables but no alembic_version: revision 0001 brings it to the same schema as a new one."""

import sqlalchemy as sa
from alembic import command
from alembic.config import Config


def alembic_config(connection=None) -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", "incident_agent.persistence:migrations")
    cfg.attributes["connection"] = connection
    return cfg


def upgrade(engine: sa.Engine, revision: str = "head") -> None:
    with engine.begin() as conn:
        command.upgrade(alembic_config(conn), revision)


def current_revision(engine: sa.Engine) -> str | None:
    from alembic.runtime.migration import MigrationContext

    with engine.connect() as conn:
        return MigrationContext.configure(conn).get_current_revision()
