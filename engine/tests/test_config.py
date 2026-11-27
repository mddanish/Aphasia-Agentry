import stat

from aphasia import config
from aphasia.cli import _attacker
from aphasia.providers import LiteLLMProvider


def _proxy_cfg():
    c = config.Config(mode="proxy")
    c.attacker = config.LLMCfg(model="gpt-4o-mini", enabled=True)
    c.upstream = config.LLMCfg(model="ollama_chat/qwen2.5:7b-instruct", api_base="http://127.0.0.1:11434",
                               enabled=True)
    c.proxy = config.ProxyCfg(enabled=True)
    return c


def test_first_run_and_roundtrip(tmp_path):
    assert config.is_first_run(tmp_path)
    c = _proxy_cfg()
    c.secrets = {config.ATTACKER_KEY: "sk-att", config.UPSTREAM_KEY: "sk-up"}
    config.save(c, tmp_path)
    assert not config.is_first_run(tmp_path)
    text = (tmp_path / "config.toml").read_text()
    assert "sk-att" not in text and "sk-up" not in text
    assert stat.S_IMODE((tmp_path / "secrets.env").stat().st_mode) == 0o600
    back = config.load(tmp_path)
    assert back.attacker.model == "gpt-4o-mini" and back.upstream.model.startswith("ollama_chat/")
    assert back.secret(config.ATTACKER_KEY) == "sk-att" and back.secret(config.UPSTREAM_KEY) == "sk-up"


def test_env_overrides_file(tmp_path, monkeypatch):
    config.save(_proxy_cfg(), tmp_path)
    monkeypatch.setenv("APHASIA_ATTACKER_MODEL", "anthropic/claude-x")
    monkeypatch.setenv(config.ATTACKER_KEY, "from-env")
    c = config.load(tmp_path)
    assert c.attacker.model == "anthropic/claude-x" and c.secret(config.ATTACKER_KEY) == "from-env"
    assert c.upstream.model.startswith("ollama_chat/")  # upstream untouched by attacker env


def test_attacker_through_proxy_is_blocked():
    c = _proxy_cfg()
    c.secrets = {config.ATTACKER_KEY: "k"}
    c.attacker.api_base = "http://127.0.0.1:4000/v1"
    assert any("attacker: api_base points at the Aphasia proxy" in p for p in config.problems(c))


def test_generic_base_url_env_pointing_at_proxy_is_blocked(monkeypatch):
    monkeypatch.setenv("OPENAI_BASE_URL", "http://127.0.0.1:4000/v1")
    assert any("OPENAI_BASE_URL" in p for p in config.problems(_proxy_cfg()))


def test_upstream_loop_and_missing_model():
    c = _proxy_cfg()
    c.upstream.api_base = "http://127.0.0.1:4000"
    assert any("loop" in p for p in config.problems(c))
    c.upstream.model = ""
    assert any("upstream: model is required" in p for p in config.problems(c))


def test_same_key_warning():
    c = _proxy_cfg()
    c.secrets = {config.ATTACKER_KEY: "k", config.UPSTREAM_KEY: "k"}
    assert any("same API key" in w for w in config.warnings(c))
    assert config.redacted(c)["secrets"][config.ATTACKER_KEY] == "set (file)"


def test_cli_attacker_uses_attacker_config_only(monkeypatch):
    c = _proxy_cfg()
    c.attacker.api_base = "http://ollama-attacker:11434"
    c.secrets = {config.ATTACKER_KEY: "sk-att", config.UPSTREAM_KEY: "sk-up"}
    config.save(c)  # APHASIA_HOME is isolated by conftest

    class A:
        model = None
        api_base = None
    p = _attacker(A())
    assert isinstance(p, LiteLLMProvider)
    assert (p.model, p.api_base, p.api_key) == ("gpt-4o-mini", "http://ollama-attacker:11434", "sk-att")


def test_provider_passes_api_key(monkeypatch):
    import litellm
    seen = {}

    def fake(**kw):
        seen.update(kw)
        return {"choices": [{"message": {"content": "hi"}}]}
    monkeypatch.setattr(litellm, "completion", fake)
    LiteLLMProvider("gpt-4o-mini", api_key="sk-att").plan("g", [])
    assert seen["api_key"] == "sk-att"


def test_proxy_url_check_handles_aliases_and_ports():
    c = _proxy_cfg()
    c.secrets = {config.ATTACKER_KEY: "k"}
    for base, blocked in (("http://localhost:4000/v1", True), ("http://127.0.0.1:4000", True),
                          ("http://[::1]:4000/v1", True), ("http://127.0.0.1:40001/v1", False),
                          ("http://10.0.0.5:4000/v1", False), ("https://api.openai.com/v1", False)):
        c.attacker.api_base = base
        hit = any(p.startswith("attacker: api_base points") for p in config.problems(c))
        assert hit is blocked, base
    c.proxy.listen = "0.0.0.0:4000"
    c.attacker.api_base = "http://127.0.0.1:4000/v1"
    assert any(p.startswith("attacker: api_base points") for p in config.problems(c))


def test_proxy_mode_requires_proxy_enabled():
    c = _proxy_cfg()
    c.proxy.enabled = False
    assert any(p.startswith("mode: proxy mode needs") for p in config.problems(c))


def test_hosted_models_need_their_own_role_key(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "shared-key")  # must NOT satisfy the check
    c = _proxy_cfg()
    c.upstream.model, c.upstream.api_base = "gpt-4o", ""
    probs = config.problems(c)
    assert any(config.ATTACKER_KEY in p for p in probs) and any(config.UPSTREAM_KEY in p for p in probs)
    assert not config.needs_key("ollama_chat/qwen2.5:7b-instruct", "")
    assert not config.needs_key("openai/local", "http://127.0.0.1:8080/v1")
    c.secrets = {config.ATTACKER_KEY: "a", config.UPSTREAM_KEY: "u"}
    assert config.problems(c) == []


def test_cli_attacker_refuses_shared_key_when_proxy_enabled():
    import pytest
    from aphasia.providers import ProviderError
    config.save(_proxy_cfg())  # proxy enabled, no attacker key

    class A:
        model = None
        api_base = None
    with pytest.raises(ProviderError, match=config.ATTACKER_KEY):
        _attacker(A())


def test_cli_attacker_legacy_fallback_warns_in_direct_mode(capsys):
    class A:
        model = "gpt-4o-mini"
        api_base = None
    p = _attacker(A())  # no config at all: legacy behaviour, litellm env vars, with a warning
    assert p.api_key is None and "not set" in capsys.readouterr().err


def test_secret_source_and_redaction(monkeypatch):
    c = _proxy_cfg()
    c.secrets = {config.UPSTREAM_KEY: "u"}
    monkeypatch.setenv(config.ATTACKER_KEY, "from-env")
    r = config.redacted(c)["secrets"]
    assert r[config.ATTACKER_KEY] == "set (env)" and r[config.UPSTREAM_KEY] == "set (file)"
