"""Checkpointer factory: Postgres when DATABASE_URL is set, memory otherwise.

With Postgres, every step of every investigation is saved. A paused run
(waiting for an answer) survives a restart and can be resumed by thread id.
"""

import os

from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.checkpoint.memory import InMemorySaver

from incident_agent.agent.graph import SERDE


def make_checkpointer(database_url: str | None = None) -> BaseCheckpointSaver:
    url = database_url or os.environ.get("DATABASE_URL")
    if not url:
        return InMemorySaver(serde=SERDE)

    from langgraph.checkpoint.postgres import PostgresSaver
    from psycopg.rows import dict_row
    from psycopg_pool import ConnectionPool

    pool = ConnectionPool(url, max_size=10, open=True,
                          kwargs={"autocommit": True, "prepare_threshold": 0, "row_factory": dict_row})
    saver = PostgresSaver(pool, serde=SERDE)
    saver.setup()  # creates checkpoint tables on first run
    return saver
