import pytest


@pytest.fixture(autouse=True)
def _isolated_aphasia_home(tmp_path, monkeypatch):
    """Never read or write the developer's real ~/.config/aphasia during tests."""
    monkeypatch.setenv("APHASIA_HOME", str(tmp_path / "aphasia-home"))
    for var in ("APHASIA_ATTACKER_MODEL", "APHASIA_ATTACKER_API_BASE", "APHASIA_ATTACKER_API_KEY",
                "APHASIA_UPSTREAM_MODEL", "APHASIA_UPSTREAM_API_BASE", "APHASIA_UPSTREAM_API_KEY",
                "APHASIA_PROXY_KEY", "APHASIA_WAZUH_PASSWORD", "APHASIA_WAZUH_URL",
                "OPENAI_BASE_URL", "OPENAI_API_BASE", "ANTHROPIC_BASE_URL", "ANTHROPIC_API_BASE"):
        monkeypatch.delenv(var, raising=False)
