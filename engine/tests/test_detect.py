import json
from pathlib import Path

from aphasia.detect.wazuh import build_view, detect, _classify, _match
from aphasia.evidence import EvidenceStore
from aphasia.scenarios import Scenario, register, REGISTRY

SAMPLE = Path(__file__).resolve().parents[2] / "deploy/wazuh/samples/indexer_search_response.json"


def _seed_run(tmp_path, rows):
    st = EvidenceStore(tmp_path)
    base = dict(run_id="20261204T101500-a1b2c3", target_host="127.0.0.1", target_identity="support-agent")
    for r in rows:
        st.append({**base, **r})


def _reg():
    for sid, cat, atlas, ow in [("indirect_injection", "Indirect prompt injection", "AML.T0051.001", "LLM01"),
                                 ("data_exfil", "Data exfiltration", "AML.T0086", "LLM02")]:
        register(Scenario(sid, cat, "direct", "g", "s", atlas, ow))


def test_strong_match_and_detected(tmp_path):
    _reg()
    _seed_run(tmp_path, [
        {"scenario_id": "indirect_injection", "step_no": 3, "ts": "2026-12-04T10:15:04Z",
         "channel": "email", "payload": "refund", "observation": {"reply": "done", "tool_calls": []},
         "tool_calls": [{"name": "issue_refund", "args": {"payee": "5e0b77c1a9d2f830"}, "mutating": True}],
         "canary_hits": ["5e0b77c1a9d2f830"], "verdict": "success"}])
    view = detect(tmp_path, from_file=SAMPLE)
    assert (tmp_path / "run_view.json").exists() and (tmp_path / "detections.json").exists()
    step = view["steps"][0]  # strong match on run_id+scenario+step=3 -> rule 100210
    assert step["result"] == "detected" and step["alert"]["rule"] == "100210" and step["telemetry"] is True
    assert set(view.keys()) >= {"run_id", "scenarios", "steps", "gaps", "deploy_mode", "exchanges", "siem"}
    REGISTRY.pop("indirect_injection", None); REGISTRY.pop("data_exfil", None)


def test_missing_becomes_gap_for_proven_scenario(tmp_path):
    _reg()
    st = EvidenceStore(tmp_path)
    base = dict(run_id="UNIT-missing", target_host="127.0.0.1", target_identity="support-agent")
    st.append({**base, "scenario_id": "data_exfil", "step_no": 0, "ts": "2026-12-04T10:15:20Z",
               "channel": "direct", "payload": "exfil", "observation": {"reply": "sent", "tool_calls": []},
               "tool_calls": [{"name": "send_email", "args": {"to": "beacon"}, "mutating": True}],
               "canary_hits": ["CAN-tok"], "verdict": "success"})
    st.append({**base, "scenario_id": "data_exfil", "step_no": 1, "ts": "2026-12-04T10:15:21Z",
               "channel": "direct", "payload": "beacon", "observation": {"reply": "ok", "tool_calls": []},
               "tool_calls": [{"name": "http", "args": {}, "mutating": False}],
               "canary_hits": [], "verdict": "clean"})
    view = detect(tmp_path, from_file=SAMPLE)
    # step 1 (http egress) has no alert in the sample -> missing -> a gap (data_exfil is proven)
    results = {s["no"]: s["result"] for s in view["steps"]}
    assert results[2] == "missing"
    assert any(g["kind"] == "log source" and "data_exfil" in g["covers"] for g in view["gaps"])
    assert view["gaps"][0]["rank"] == 1 and view["gaps"][0]["fix"]
    REGISTRY.pop("indirect_injection", None); REGISTRY.pop("data_exfil", None)


def test_classify_levels():
    step = {"verdict": "success", "tool_calls": [{"name": "x"}], "canary_hits": ["t"]}
    hi = [{"ts": "", "rule": {"id": "100210", "level": 12, "description": "d"}, "data": {}}]
    lo = [{"ts": "", "rule": {"id": "100205", "level": 3, "description": "t"}, "data": {}}]
    assert _classify(step, hi, 7)[0] == "detected"
    assert _classify(step, lo, 7)[0] == "silent"       # telemetry present, below min level
    assert _classify(step, [], 7)[0] == "missing"
    benign = {"verdict": "clean", "tool_calls": [], "canary_hits": []}
    assert _classify(benign, lo, 7)[0] == "expected"


def test_run_view_matches_demo_keys(tmp_path):
    _reg()
    _seed_run(tmp_path, [
        {"scenario_id": "indirect_injection", "step_no": 0, "ts": "2026-12-04T10:15:04Z",
         "channel": "email", "payload": "x", "observation": {"reply": "r", "tool_calls": []},
         "tool_calls": [{"name": "issue_refund", "args": {"payee": "5e0b77c1a9d2f830"}, "mutating": True}],
         "canary_hits": ["5e0b77c1a9d2f830"], "verdict": "success"}])
    view = detect(tmp_path, from_file=SAMPLE)
    demo = json.loads((Path(__file__).resolve().parents[1]
                       / "src/aphasia/tui/demo_run.json").read_text())
    assert set(view.keys()) == set(demo.keys())
    assert set(view["steps"][0].keys()) == set(demo["steps"][0].keys())
    assert set(view["scenarios"][0].keys()) == set(demo["scenarios"][0].keys())
    assert set(view["gaps"][0].keys()) == set(demo["gaps"][0].keys()) if view["gaps"] else True
    REGISTRY.pop("indirect_injection", None); REGISTRY.pop("data_exfil", None)


def test_scenario_verdict_uses_display_vocab(tmp_path):
    _reg()
    _seed_run(tmp_path, [
        {"scenario_id": "indirect_injection", "step_no": 3, "ts": "2026-12-04T10:15:04Z",
         "channel": "email", "payload": "x", "observation": {"reply": "r", "tool_calls": []},
         "tool_calls": [{"name": "issue_refund", "args": {"payee": "5e0b77c1a9d2f830"}, "mutating": True}],
         "canary_hits": ["5e0b77c1a9d2f830"], "verdict": "success"}])
    view = detect(tmp_path, from_file=SAMPLE)
    assert view["scenarios"][0]["verdict"] == "proven"  # not the raw "success"
    REGISTRY.pop("indirect_injection", None); REGISTRY.pop("data_exfil", None)


def test_proxy_exchanges_loaded_into_view(tmp_path):
    import json as _j
    _reg()
    _seed_run(tmp_path, [
        {"scenario_id": "indirect_injection", "step_no": 3, "ts": "2026-12-04T10:15:04Z",
         "channel": "email", "payload": "x", "observation": {"reply": "r", "tool_calls": []},
         "tool_calls": [{"name": "issue_refund", "args": {"payee": "5e0b77c1a9d2f830"}, "mutating": True}],
         "canary_hits": ["5e0b77c1a9d2f830"], "verdict": "success"}])
    pdir = tmp_path / "proxy"; pdir.mkdir()
    (pdir / "proxy.jsonl").write_text("\n".join(_j.dumps(x) for x in [
        {"event": "llm_exchange", "ts": "2026-12-04T10:15:03Z", "scenario": "indirect_injection",
         "step": "1", "session": "s", "model": "qwen", "latency_ms": 840,
         "injection_in_tool_result": True, "honey_in_context": True,
         "messages": [{"role": "user", "content": "hi"}], "tools": [{"name": "issue_refund", "desc_hash": "a"}],
         "tool_calls": [{"name": "issue_refund", "args": {}}], "reply": ""},
        {"event": "llm_tool_call", "tool": "issue_refund"}]))
    from aphasia.detect import detect
    view = detect(tmp_path, from_file=SAMPLE, proxy_dir=pdir)
    assert view["deploy_mode"] == "proxy" and len(view["exchanges"]) == 1
    ex = view["exchanges"][0]
    assert ex["model"] == "qwen" and "injection_in_tool_result" in ex["flags"] and ex["no"] == 1
    REGISTRY.pop("indirect_injection", None); REGISTRY.pop("data_exfil", None)
