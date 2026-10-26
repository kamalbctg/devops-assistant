"""baseline: the schema before Alembic

Creates the tables on an empty database. On a database made by an older version (before Alembic)
it adds only what is missing and repeats the data fix-ups the old start-up code did, so both end up
with the same schema. Later revisions can assume this schema.

Revision ID: 0001
Revises:
Create Date: 2026-10-25 21:51:28.559578
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0001'
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

RETIRED_MODELS = {"claude-haiku-4-5": "claude-haiku-5-5"}  # frozen copy of config.llm.LEGACY_MODELS at this revision


def create_missing_tables(existing: set[str]) -> None:
    if 'agents' not in existing:
        op.create_table('agents',
        sa.Column('id', sa.String(length=32), nullable=False),
        sa.Column('name', sa.String(length=200), nullable=False),
        sa.Column('type', sa.String(length=50), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('services', sa.JSON(), nullable=False),
        sa.Column('connector_ids', sa.JSON(), nullable=False),
        sa.Column('budget', sa.JSON(), nullable=False),
        sa.Column('timezone', sa.String(length=64), nullable=False),
        sa.Column('llm', sa.JSON(), nullable=True),
        sa.Column('prompt', sa.Text(), nullable=True),
        sa.Column('prompt_version', sa.Integer(), nullable=True),
        sa.Column('analysis_fields', sa.JSON(), nullable=True),
        sa.Column('retention', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.Float(), nullable=False),
        sa.Column('updated_at', sa.Float(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name')
        )
    if 'connectors' not in existing:
        op.create_table('connectors',
        sa.Column('id', sa.String(length=32), nullable=False),
        sa.Column('name', sa.String(length=200), nullable=False),
        sa.Column('type', sa.String(length=50), nullable=False),
        sa.Column('mode', sa.String(length=10), nullable=False),
        sa.Column('provides', sa.JSON(), nullable=False),
        sa.Column('settings', sa.JSON(), nullable=False),
        sa.Column('secrets', sa.Text(), nullable=True),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('status_detail', sa.Text(), nullable=True),
        sa.Column('tested_at', sa.Float(), nullable=True),
        sa.Column('created_at', sa.Float(), nullable=False),
        sa.Column('updated_at', sa.Float(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name')
        )
    if 'investigations' not in existing:
        op.create_table('investigations',
        sa.Column('id', sa.String(length=32), nullable=False),
        sa.Column('agent_id', sa.String(length=32), nullable=False),
        sa.Column('agent_name', sa.String(length=200), nullable=True),
        sa.Column('question', sa.Text(), nullable=False),
        sa.Column('source', sa.String(length=30), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('created', sa.Float(), nullable=False),
        sa.Column('dedup_key', sa.String(length=300), nullable=True),
        sa.Column('data', sa.JSON(), nullable=False),
        sa.PrimaryKeyConstraint('id')
        )
    if 'prompt_versions' not in existing:
        op.create_table('prompt_versions',
        sa.Column('agent_id', sa.String(length=32), nullable=False),
        sa.Column('version', sa.Integer(), nullable=False),
        sa.Column('prompt', sa.Text(), nullable=False),
        sa.Column('note', sa.String(length=300), nullable=True),
        sa.Column('created_at', sa.Float(), nullable=False),
        sa.PrimaryKeyConstraint('agent_id', 'version')
        )
    if 'settings' not in existing:
        op.create_table('settings',
        sa.Column('id', sa.String(length=50), nullable=False),
        sa.Column('value', sa.JSON(), nullable=False),
        sa.Column('secrets', sa.Text(), nullable=True),
        sa.Column('updated_at', sa.Float(), nullable=False),
        sa.PrimaryKeyConstraint('id')
        )


def add_missing_columns(bind) -> set[str]:
    """Columns added to older databases over time. Returns the agents columns that were added."""
    insp = sa.inspect(bind)
    if 'notes' not in {c['name'] for c in insp.get_columns('connectors')}:
        op.add_column('connectors', sa.Column('notes', sa.Text(), nullable=True))
    have = {c['name'] for c in insp.get_columns('agents')}
    new = [sa.Column('type', sa.String(length=50), nullable=False, server_default='incident_investigation'),
           sa.Column('analysis_fields', sa.JSON(), nullable=True),
           sa.Column('prompt', sa.Text(), nullable=True),
           sa.Column('retention', sa.JSON(), nullable=True),
           sa.Column('prompt_version', sa.Integer(), nullable=True),
           sa.Column('llm', sa.JSON(), nullable=True)]
    added = set()
    for col in new:
        if col.name not in have:
            op.add_column('agents', col)
            added.add(col.name)
    return added


def fix_old_rows(bind, added: set[str]) -> None:
    from incident_agent.agent.prompts import DEFAULT_INSTRUCTIONS

    agents = sa.table('agents', sa.column('id'), sa.column('prompt'), sa.column('prompt_version'),
                      sa.column('llm', sa.JSON), sa.column('updated_at'))
    versions = sa.table('prompt_versions', sa.column('agent_id'), sa.column('version'), sa.column('prompt'),
                        sa.column('note'), sa.column('created_at'))
    # agents saved before prompts were always stored: store the default
    bind.execute(agents.update().where(agents.c.prompt.is_(None)).values(prompt=DEFAULT_INSTRUCTIONS.strip()))
    # agents saved before prompt versioning: their prompt becomes v1
    have = {r[0] for r in bind.execute(sa.select(versions.c.agent_id).distinct())}
    for a in bind.execute(sa.select(agents.c.id, agents.c.prompt, agents.c.updated_at)).all():
        if a.id not in have and a.prompt:
            bind.execute(versions.insert().values(agent_id=a.id, version=1, prompt=a.prompt,
                                                  note="first saved version", created_at=a.updated_at))
    # agents saved before the in-use pointer: the newest version is the one in use
    for a in bind.execute(sa.select(agents.c.id).where(agents.c.prompt_version.is_(None))).all():
        v = bind.execute(sa.select(sa.func.max(versions.c.version)).where(versions.c.agent_id == a.id)).scalar()
        if v:
            bind.execute(agents.update().where(agents.c.id == a.id).values(prompt_version=v))
    # agents created before the llm column ran without an LLM: keep that until edited
    if 'llm' in added:
        bind.execute(agents.update().values(llm={"model": "scripted", "fast_model": "claude-haiku-5-5",
                                                 "effort": "medium"}))
    # models retired from the list: move saved agents to the successor
    for a in bind.execute(sa.select(agents.c.id, agents.c.llm)).all():
        if a.llm and any(v in RETIRED_MODELS for v in a.llm.values()):
            bind.execute(agents.update().where(agents.c.id == a.id)
                         .values(llm={k: RETIRED_MODELS.get(v, v) for k, v in a.llm.items()}))


def upgrade() -> None:
    bind = op.get_bind()
    create_missing_tables(set(sa.inspect(bind).get_table_names()))
    fix_old_rows(bind, add_missing_columns(bind))


def downgrade() -> None:
    op.drop_table('settings')
    op.drop_table('prompt_versions')
    op.drop_table('investigations')
    op.drop_table('connectors')
    op.drop_table('agents')
