import importlib.util
import sys
from pathlib import Path

import pytest

_FIXTURE = Path(__file__).resolve().parents[2] / "fixture"


def _load(mod_name: str, path: Path):
    """Load a fixture app.py under a unique module name (both fixtures define `app`)."""
    spec = importlib.util.spec_from_file_location(mod_name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def fixture_agent():
    return _load("fixture_agent_app", _FIXTURE / "agent" / "app.py")


@pytest.fixture
def fixture_llm_agent():
    return _load("fixture_llm_agent_app", _FIXTURE / "llm-agent" / "app.py")


@pytest.fixture(autouse=True)
def _isolated_aphasia_home(tmp_path, monkeypatch):
    """Never read or write the developer's real ~/.config/aphasia during tests."""
    monkeypatch.setenv("APHASIA_HOME", str(tmp_path / "aphasia-home"))
    for var in ("APHASIA_ATTACKER_MODEL", "APHASIA_ATTACKER_API_BASE", "APHASIA_ATTACKER_API_KEY",
                "APHASIA_UPSTREAM_MODEL", "APHASIA_UPSTREAM_API_BASE", "APHASIA_UPSTREAM_API_KEY",
                "APHASIA_PROXY_KEY", "APHASIA_WAZUH_PASSWORD", "APHASIA_WAZUH_URL",
                "OPENAI_BASE_URL", "OPENAI_API_BASE", "ANTHROPIC_BASE_URL", "ANTHROPIC_API_BASE"):
        monkeypatch.delenv(var, raising=False)
