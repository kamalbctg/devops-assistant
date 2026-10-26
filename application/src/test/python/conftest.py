import pytest
from incident_agent.connectors import datadog

LEARN_ALIASES = datadog.Datadog.aliases  # the real one, for the tests that cover it


@pytest.fixture(autouse=True)
def no_apm_aliases(monkeypatch):
    """Stubbed Datadog APIs don't answer the alias lookup: tests see the service names they pass."""
    monkeypatch.setattr(datadog.Datadog, "aliases", lambda self: {})
    datadog._ALIASES.clear()
