from pathlib import Path
from aphasia.cli import exit_code, main
from aphasia.run import RunResult, ScenarioResult


def rr(v):
    return RunResult("r", Path("."), [ScenarioResult("s", v, [], 1)])


def test_exit_code():
    assert exit_code(rr("success")) != 0
    assert exit_code(rr("clean")) == 0


def test_list(capsys):
    assert main(["list"]) == 0
    out = capsys.readouterr().out
    assert all(i in out for i in ["direct_injection", "denial_of_wallet", "system_prompt_leak"])
    assert all(h in out for h in ["Scenario", "OWASP", "ATLAS", "Channel", "Seeds", "Category"])
    assert "│" in out and "OWASP LLM Top 10" in out  # bordered table + summary
    assert all(f"LLM{n:02d}" in out for n in range(1, 11))  # all 10 OWASP ids


def test_unreachable_fail_soft(capsys, tmp_path):
    rc = main(["run", "--mode", "adaptive", "--api-base", "http://127.0.0.1:1",
               "--model", "ollama/x", "--target", "http://127.0.0.1:1",
               "--out", str(tmp_path / "o")])
    err = capsys.readouterr().err
    assert rc == 2 and "error" in err.lower() and "Traceback" not in err


def test_report_from_evidence(tmp_path):
    import json
    base = dict(ts="t", target_host="h", target_identity="i", channel="direct", payload="p",
                observation=None, tool_calls=[], run_id="rid")
    rows = [dict(base, scenario_id="a", step_no=0, canary_hits=[], verdict="clean"),
            dict(base, scenario_id="a", step_no=1, canary_hits=["T"], verdict="success"),
            dict(base, scenario_id="b", step_no=0, canary_hits=[], verdict="capped")]
    (tmp_path / "evidence.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    assert main(["report", "--run-dir", str(tmp_path)]) == 0
    j = json.loads((tmp_path / "report.json").read_text())
    assert [(s["scenario_id"], s["verdict"], s["steps"]) for s in j["scenarios"]] == [
        ("a", "success", 2), ("b", "capped", 1)]
    assert j["exposure_score"] > 0 and (tmp_path / "report.html").exists()


def test_run_success_exit_1(monkeypatch, tmp_path):
    from aphasia import cli
    from aphasia.providers import StubProvider
    from aphasia.types import Observation, Step

    class Conn:
        host, identity = "h", "i"
        def plant(self, c): self.c = c
        def deliver(self, step): return Observation(reply=f"leak {self.c[0].token}", tool_calls=[])

    monkeypatch.setattr(cli, "_connector", lambda t: Conn())
    # hybrid mode delivers a seed payload first; the echoing connector returns the canary
    assert main(["run", "--scenario", "direct_injection", "--out", str(tmp_path / "o")]) == 1


def test_fixture_connector_targets_chat_and_seed():
    from aphasia.cli import _connector
    c = _connector("fixture")
    assert c.base_url.endswith("/chat")
    assert c.plant_url.endswith("/seed")


def test_payloads_subcommand(capsys):
    assert main(["payloads"]) == 0
    out = capsys.readouterr().out
    assert "direct_injection" in out and "Total:" in out and "│" in out


def test_seed_mode_builds_no_llm(monkeypatch, tmp_path):
    import aphasia.cli as cli
    from aphasia.types import Observation

    class EchoConn:
        host, identity = "h", "i"
        def plant(self, c): pass
        def deliver(self, step): return Observation(reply="nothing", tool_calls=[])

    def boom(*a, **k):
        raise AssertionError("Ollama provider must not be constructed in seed mode")

    monkeypatch.setattr(cli, "_connector", lambda t: EchoConn())
    monkeypatch.setattr(cli, "LiteLLMProvider", boom)
    rc = cli.main(["run", "--mode", "seed", "--target", "x", "--out", str(tmp_path)])
    assert rc == 0  # no success, no error, and the LLM was never built


def test_help_and_version(capsys):
    import pytest
    for args in (["--help"], ["run", "--help"], ["--version"]):
        with pytest.raises(SystemExit) as e:
            main(args)
        assert e.value.code == 0
    # top-level help names commands + examples; run help documents --mode
    with pytest.raises(SystemExit):
        main(["--help"])
    top = capsys.readouterr().out
    assert all(c in top for c in ["list", "payloads", "run", "report", "Examples:"])
