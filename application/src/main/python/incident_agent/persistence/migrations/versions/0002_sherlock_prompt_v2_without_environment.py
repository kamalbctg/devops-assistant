"""sherlock prompt v2 without environment section

Data only. The Sherlock agent's prompt v2 had a section "2. Use the right environment" (do not use
stage data for a prod alert). The team decided every connector is used, prod or stage, so the
section is removed from v2 itself (not saved as a new version), and the later sections are
renumbered. If the change had been saved as v3 instead, v3 is folded back into v2.

First applied by hand on 2026-10-25; on that database this revision finds nothing to do.
On a database without the Sherlock agent it does nothing.

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-25 22:30:33.360999
"""
import re
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0002'
down_revision: str | None = '0001'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

AGENT_ID = "d0a9078b6798"  # Sherlock
SECTION_START, NEXT_SECTION = "2. Use the right environment", "3. Search for the condition"
NOTE = "Ported from investigate-alert skill (environment section removed)"

agents = sa.table("agents", sa.column("id"), sa.column("prompt"), sa.column("prompt_version"))
versions = sa.table("prompt_versions", sa.column("agent_id"), sa.column("version"), sa.column("prompt"),
                    sa.column("note"))


def without_environment(prompt: str) -> str:
    """Drop the section and renumber the sections after it (3. -> 2., ...)."""
    start, end = prompt.index(SECTION_START), prompt.index(NEXT_SECTION)
    rest = re.sub(r"(?m)^(\d+)\. ", lambda m: f"{int(m.group(1)) - 1}. ", prompt[end:])
    return prompt[:start] + rest


def upgrade() -> None:
    bind = op.get_bind()
    of_agent = versions.c.agent_id == AGENT_ID
    v2 = bind.execute(sa.select(versions.c.prompt).where(of_agent, versions.c.version == 2)).scalar()
    if v2 is None or SECTION_START not in v2 or NEXT_SECTION not in v2:
        return  # no Sherlock, or already done
    text = without_environment(v2)
    bind.execute(versions.update().where(of_agent, versions.c.version == 2).values(prompt=text, note=NOTE))
    # the same edit saved as v3 (how it was first done): fold it into v2
    bind.execute(versions.delete().where(of_agent, versions.c.version == 3, versions.c.prompt == text))
    in_use = bind.execute(sa.select(agents.c.prompt_version).where(agents.c.id == AGENT_ID)).scalar()
    if in_use in (2, 3):
        bind.execute(agents.update().where(agents.c.id == AGENT_ID).values(prompt=text, prompt_version=2))


def downgrade() -> None:
    pass  # the removed section is not kept; a backup of the old v2 text was taken when it was first applied
