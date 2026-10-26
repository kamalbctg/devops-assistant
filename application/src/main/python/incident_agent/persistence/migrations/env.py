"""Alembic environment. Runs inside the app (Store calls schema.upgrade on start) and from the CLI
(`uv run alembic ...` in the project folder, which uses DATABASE_URL or the local SQLite file)."""

import os

import sqlalchemy as sa
from alembic import context
from incident_agent.persistence.store import database_url, meta

config = context.config


def include_object(obj, name, type_, reflected, compare_to):
    # The database also holds tables Alembic does not own (LangGraph's checkpoints): leave them alone.
    return not (type_ == "table" and reflected and compare_to is None)


def run(connection):
    context.configure(connection=connection, target_metadata=meta, include_object=include_object,
                      render_as_batch=connection.dialect.name == "sqlite",  # SQLite can't ALTER most things
                      compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


connection = config.attributes.get("connection")
if connection is not None:  # called from the app with an open connection
    run(connection)
else:
    engine = sa.create_engine(database_url(os.environ.get("DATA_DIR", ".data")))
    with engine.begin() as conn:
        run(conn)
