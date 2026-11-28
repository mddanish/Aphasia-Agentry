import sys
from pathlib import Path

import pytest

# Make the Flask fixture agent importable as `app` for telemetry tests.
_FIXTURE_AGENT = Path(__file__).resolve().parents[2] / "fixture" / "agent"
if _FIXTURE_AGENT.is_dir() and str(_FIXTURE_AGENT) not in sys.path:
    sys.path.insert(0, str(_FIXTURE_AGENT))


@pytest.fixture(autouse=True)
def _isolated_aphasia_home(tmp_path, monkeypatch):
    """Never read or write the developer's real ~/.config/aphasia during tests."""
    monkeypatch.setenv("APHASIA_HOME", str(tmp_path / "aphasia-home"))
    for var in ("APHASIA_ATTACKER_MODEL", "APHASIA_ATTACKER_API_BASE", "APHASIA_ATTACKER_API_KEY",
                "APHASIA_UPSTREAM_MODEL", "APHASIA_UPSTREAM_API_BASE", "APHASIA_UPSTREAM_API_KEY",
                "APHASIA_PROXY_KEY", "APHASIA_WAZUH_PASSWORD", "APHASIA_WAZUH_URL",
                "OPENAI_BASE_URL", "OPENAI_API_BASE", "ANTHROPIC_BASE_URL", "ANTHROPIC_API_BASE"):
        monkeypatch.delenv(var, raising=False)
