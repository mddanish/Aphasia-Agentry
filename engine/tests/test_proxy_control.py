import json
from pathlib import Path

import pytest

from aphasia import config as cfg
from aphasia.proxy import control


def _cfg(tmp_path):
    c = cfg.Config(mode="proxy")
    c.upstream = cfg.LLMCfg(model="ollama_chat/qwen2.5:7b-instruct", api_base="http://127.0.0.1:11434",
                            enabled=True)
    c.proxy = cfg.ProxyCfg(enabled=True, dir=str(tmp_path / "proxy"), listen="127.0.0.1:4111")
    c.secrets = {cfg.UPSTREAM_KEY: "sk-up", cfg.PROXY_KEY: "sk-aphasia-fixed"}
    return c


def test_config_yaml_and_recorder_written_no_secrets(tmp_path):
    c = _cfg(tmp_path)
    d = Path(c.proxy.dir); d.mkdir(parents=True)
    p = control._write_config(d, c)
    control._copy_recorder(d)
    text = p.read_text()
    assert "model_name: agent-model" in text and "ollama_chat/qwen2.5:7b-instruct" in text
    assert "os.environ/APHASIA_UPSTREAM_API_KEY" in text and "os.environ/APHASIA_PROXY_KEY" in text
    assert "sk-up" not in text and "sk-aphasia" not in text        # never a literal key
    assert (d / "aphasia_recorder.py").read_text().startswith('"""')


def test_clean_env_excludes_attacker_and_generic_keys(tmp_path, monkeypatch):
    monkeypatch.setenv("APHASIA_ATTACKER_API_KEY", "ATT")
    monkeypatch.setenv("OPENAI_API_KEY", "OAI")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "ANT")
    env = control._clean_env(tmp_path, "sk-proxy", "sk-up", full=True)
    assert env["APHASIA_PROXY_KEY"] == "sk-proxy" and env["APHASIA_UPSTREAM_API_KEY"] == "sk-up"
    assert env["APHASIA_PROXY_FULL"] == "1"
    for leaked in ("APHASIA_ATTACKER_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"):
        assert leaked not in env


def test_start_spawns_clean_and_prints_settings(tmp_path, monkeypatch):
    c = _cfg(tmp_path)
    captured = {}

    class FakeProc:
        pid = 4242
        returncode = None
        def poll(self):
            return None

    def fake_spawn(cmd, env=None, stdout=None, stderr=None):
        captured["cmd"] = cmd
        captured["env"] = env
        return FakeProc()

    monkeypatch.setattr(control.shutil, "which", lambda x: "/usr/bin/uvx")
    monkeypatch.setattr(control, "_health_ok", lambda base, timeout=1.5: True)
    s = control.start(c, spawn=fake_spawn, wait_s=3)
    assert s["api_key"] == "sk-aphasia-fixed" and s["model"] == "agent-model"
    assert s["base_url"] == "http://127.0.0.1:4111/v1" and s["pid"] == 4242
    assert captured["cmd"][:3] == ["uvx", "--from", "litellm[proxy]==1.111.0"]
    assert "OPENAI_API_KEY" not in captured["env"] and "APHASIA_ATTACKER_API_KEY" not in captured["env"]
    assert (Path(c.proxy.dir) / "proxy.pid").read_text() == "4242"


def test_start_refuses_without_upstream_model(tmp_path, monkeypatch):
    c = _cfg(tmp_path); c.upstream.model = ""
    monkeypatch.setattr(control.shutil, "which", lambda x: "/usr/bin/uvx")
    with pytest.raises(ValueError, match="no upstream model"):
        control.start(c, spawn=lambda *a, **k: None)


def test_start_refuses_nonlocal_bind_without_explicit_listen(tmp_path, monkeypatch):
    c = _cfg(tmp_path); c.proxy.listen = "0.0.0.0:4111"
    monkeypatch.setattr(control.shutil, "which", lambda x: "/usr/bin/uvx")
    with pytest.raises(ValueError, match="non-local bind"):
        control.start(c, spawn=lambda *a, **k: None)


def test_run_proxy_writes_and_removes_context(tmp_path):
    from aphasia.run import run_all
    from aphasia.scenarios import Scenario
    from aphasia.types import Observation

    pdir = tmp_path / "proxy"; pdir.mkdir()
    seen = {}

    class Conn:
        host = "h"; identity = "i"
        def plant(self, c): pass
        def set_context(self, *a): pass
        def deliver(self, step):
            seen["ctx"] = json.loads((pdir / "context.json").read_text())
            return Observation(reply="nothing", tool_calls=[])

    sc = Scenario("direct_injection", "Direct prompt injection", "direct", "g", "s", "", "LLM01")
    run_all([sc], Conn(), None, tmp_path / "run", max_steps=1, mode="seed",
            payloads={"direct_injection": ["p"]}, proxy_dir=pdir)
    assert seen["ctx"]["scenario"] == "direct_injection" and "honey" in seen["ctx"]
    assert not (pdir / "context.json").exists()   # cleaned up after the run
