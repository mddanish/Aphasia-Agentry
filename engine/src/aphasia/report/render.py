import json
from html import escape
from pathlib import Path
from string import Template

from aphasia.evidence import EvidenceStore
from aphasia.run import RunResult, ScenarioResult
from aphasia.scenarios import REGISTRY
from aphasia.score import exposure_score
from aphasia.types import Canary

# Display labels. Kept here (not in scenarios.yaml) so the report can name a
# technique even for an ad-hoc scenario; the yaml stays the id source of truth.
ATLAS_NAMES = {
    "AML.T0051.000": "LLM Prompt Injection: Direct",
    "AML.T0051.001": "LLM Prompt Injection: Indirect",
    "AML.T0053": "AI Agent Tool Invocation",
    "AML.T0056": "Extract LLM System Prompt",
    "AML.T0086": "Exfiltration via AI Agent Tool Invocation",
    "AML.T0110": "AI Agent Tool Poisoning",
    "AML.T0099": "AI Agent Tool Data Poisoning",
    "AML.T0010": "AI Supply Chain Compromise",
    "AML.T0031": "Erode AI Model Integrity",
    "AML.T0034.002": "Agentic Resource Consumption",
}
OWASP_NAMES = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}
VERDICT_MEANING = {
    "success": "Exploited — canary-proven impact",
    "metered": "Unbounded consumption — cost threshold breached",
    "mirror_only": "Risky action captured, but no canary proof",
    "capped": "Not cracked within the step budget",
    "clean": "No exploit and no risky action",
    "error": "Target/provider failed — not a security result",
}
REMEDIATION = {
    "Direct prompt injection":
        "Enforce an instruction hierarchy so user text cannot override the system prompt; "
        "constrain tool calls to an allow-list and reject out-of-policy arguments.",
    "Indirect prompt injection":
        "Treat email/document/tool content as untrusted data, never instructions; label and "
        "sandbox external content; require human approval for high-risk actions it triggers.",
    "Tool misuse / excessive agency":
        "Scope the agent's service token to least privilege; validate every tool argument; "
        "add human-in-the-loop for payments, deletes and outbound email.",
    "Data exfiltration":
        "Egress-filter outbound tool calls; block rendered links/image beacons; apply DLP to "
        "tool outputs so planted secrets cannot leave.",
    "MCP supply chain / poisoning":
        "Pin and verify MCP server/tool hashes; scan tool descriptions for hidden instructions; "
        "grant least-privilege tool scopes and alert on rug-pull updates.",
    "Memory / context poisoning":
        "Isolate and expire agent memory per task/user; validate and provenance-tag anything "
        "written to memory or a RAG store; never let stored notes carry executable instructions.",
    "Improper output handling":
        "Treat model output as untrusted before any sink; escape/encode for the renderer; never "
        "pass model text into a template engine, shell, SQL or HTML without sanitisation.",
    "System prompt leakage":
        "Keep secrets out of the system prompt; fetch credentials from a vault at call time; "
        "assume the prompt is extractable and scope what it can authorise.",
    "Vector / embedding (RAG)":
        "Enforce per-document ACLs at retrieval time, not just at display; partition vector "
        "stores by tenant/user; filter retrieved context against the caller's entitlements.",
    "Misinformation":
        "Ground answers in verified sources with citations; constrain confident claims; add "
        "human review for high-stakes assertions and flag unverifiable output.",
    "Unbounded consumption":
        "Enforce per-session token/call/cost caps and rate limits; bound recursion and tool-call "
        "depth; alert and cut off on cost-spike thresholds (denial-of-wallet protection).",
}


def _proof_row(run_dir: Path) -> dict[str, dict]:
    """Per scenario, the decisive evidence row: first success row, else the last row."""
    by_scenario: dict[str, dict] = {}
    for r in EvidenceStore(Path(run_dir)).read():
        sid = r.get("scenario_id")
        if sid is None:
            continue
        cur = by_scenario.get(sid)
        if cur is None or (r["verdict"] == "success" and cur["verdict"] != "success"):
            by_scenario[sid] = r
    return by_scenario


def _all_rows(run_dir: Path) -> dict[str, list[dict]]:
    """Every evidence row per scenario, in step order — the full attack timeline."""
    by_scenario: dict[str, list[dict]] = {}
    for r in EvidenceStore(Path(run_dir)).read():
        sid = r.get("scenario_id")
        if sid is not None:
            by_scenario.setdefault(sid, []).append(r)
    for rows in by_scenario.values():
        rows.sort(key=lambda r: r.get("step_no", 0))
    return by_scenario


def _enrich(result: ScenarioResult, meta, row: dict | None, steps: list[dict] | None = None) -> dict:
    hits = [c.token for c in result.hit_canaries]
    d = {
        "scenario_id": result.scenario_id,
        "verdict": result.verdict,
        "verdict_meaning": VERDICT_MEANING.get(result.verdict, result.verdict),
        "exploited": result.verdict == "success",
        "steps": result.steps,
        "hit_canaries": hits,
    }
    if meta is not None:
        d |= {
            "category": meta.category,
            "goal": meta.goal,
            "channel": meta.channel,
            "atlas": meta.atlas,
            "atlas_name": ATLAS_NAMES.get(meta.atlas, ""),
            "owasp": meta.owasp,
            "owasp_name": OWASP_NAMES.get(meta.owasp, ""),
            "success_condition": meta.success_condition,
            "remediation": REMEDIATION.get(meta.category, ""),
        }
    if row is not None:
        obs = row.get("observation") or {}
        reply = obs.get("reply", "")
        where = "reply" if any(h in reply for h in hits) else ("tool-call args" if hits else "")
        d["proof"] = {
            "payload": row.get("payload", ""),
            "reply": reply[:400],
            "tool_calls": row.get("tool_calls", []),
            "canary_location": where,
        }
    if steps:
        d["timeline"] = [{
            "step": r.get("step_no", 0),
            "channel": r.get("channel", ""),
            "payload": (r.get("payload") or "")[:300],
            "reply": ((r.get("observation") or {}).get("reply") or "")[:300],
            "tool_calls": r.get("tool_calls", []),
            "verdict": r.get("verdict", ""),
        } for r in steps]
    return d


def write_report(run_result, run_dir: Path) -> None:
    run_dir = Path(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    score = exposure_score(run_result)
    rows = _proof_row(run_dir)
    timelines = _all_rows(run_dir)
    scen = [_enrich(r, REGISTRY.get(r.scenario_id), rows.get(r.scenario_id),
                    timelines.get(r.scenario_id))
            for r in run_result.results]

    any_row = next(iter(rows.values()), {})
    summary = {
        "total": len(scen),
        "exploited": sum(1 for s in scen if s["verdict"] == "success"),
        "metered": sum(1 for s in scen if s["verdict"] == "metered"),
        "mirror_only": sum(1 for s in scen if s["verdict"] == "mirror_only"),
        "errors": sum(1 for s in scen if s["verdict"] == "error"),
        "target_host": any_row.get("target_host", ""),
        "target_identity": any_row.get("target_identity", ""),
        "started_at": any_row.get("ts", ""),
    }
    (run_dir / "report.json").write_text(json.dumps(
        {"run_id": run_result.run_id, "exposure_score": score,
         "summary": summary, "scenarios": scen}, indent=2))

    (run_dir / "report.html").write_text(_html(run_result.run_id, score, summary, scen))


def _html(run_id: str, score: int, summary: dict, scen: list[dict]) -> str:
    verdict_label = {"success": "EXPLOITED", "metered": "COST BREACH",
                     "mirror_only": "action captured",
                     "capped": "not cracked", "clean": "clean", "error": "error"}
    cards = []
    for s in scen:
        parts = [f'<div class="card {escape(s["verdict"])}">']
        parts.append(f'<div class="chead"><span class="sid">{escape(s["scenario_id"])}</span>'
                     f'<span class="badge {escape(s["verdict"])}">'
                     f'{escape(verdict_label.get(s["verdict"], s["verdict"]))}</span></div>')
        parts.append(f'<p class="meaning">{escape(s["verdict_meaning"])} '
                     f'&middot; {s["steps"]} step(s)</p>')
        if "goal" in s:
            parts.append(f'<p><b>Attack:</b> {escape(s["category"])} '
                         f'via <code>{escape(s["channel"])}</code><br>{escape(s["goal"])}</p>')
            owasp = f'OWASP {escape(s["owasp"])} {escape(s["owasp_name"])}'.strip()
            maps = owasp
            if s["atlas"]:
                maps = f'ATLAS {escape(s["atlas"])} {escape(s["atlas_name"])}'.strip() + f' &middot; {owasp}'
            parts.append(f'<p class="map"><b>Maps to:</b> {maps}</p>')
        proof = s.get("proof")
        if s["verdict"] == "success" and proof:
            loc = escape(proof["canary_location"])
            toks = escape(", ".join(s["hit_canaries"]))
            parts.append('<div class="proof"><b>Proof (canary-backed):</b>'
                         f'<br>Canary <code>{toks}</code> surfaced in the {loc}.')
            if proof["payload"]:
                parts.append(f'<br><b>Winning payload:</b> <code>{escape(proof["payload"][:300])}</code>')
            if proof["reply"]:
                parts.append(f'<br><b>Target reply:</b> <code>{escape(proof["reply"])}</code>')
            if proof["tool_calls"]:
                parts.append(f'<br><b>Tool call captured:</b> '
                             f'<code>{escape(json.dumps(proof["tool_calls"]))[:300]}</code>')
            parts.append('</div>')
        tl = s.get("timeline")
        if tl:
            steps_html = []
            for t in tl:
                bits = [f'<div class="step"><span class="sn">step {t["step"]}</span> '
                        f'<span class="sv {escape(t["verdict"])}">{escape(t["verdict"])}</span>']
                if t["payload"]:
                    bits.append(f'<div class="turn"><b>attacker</b> '
                                f'<code>{escape(t["payload"])}</code></div>')
                if t["reply"]:
                    bits.append(f'<div class="turn"><b>target</b> '
                                f'<code>{escape(t["reply"])}</code></div>')
                if t["tool_calls"]:
                    bits.append(f'<div class="turn"><b>tools</b> '
                                f'<code>{escape(json.dumps(t["tool_calls"]))[:300]}</code></div>')
                bits.append('</div>')
                steps_html.append("".join(bits))
            parts.append(f'<details class="timeline"><summary>Step-by-step timeline '
                         f'({len(tl)} step{"s" if len(tl) != 1 else ""})</summary>'
                         f'{"".join(steps_html)}</details>')
        if s.get("remediation"):
            parts.append(f'<p class="fix"><b>Fix:</b> {escape(s["remediation"])}</p>')
        parts.append('</div>')
        cards.append("".join(parts))

    tpl = Template((Path(__file__).parent / "template.html").read_text())
    return tpl.substitute(
        run_id=escape(run_id), score=score,
        exploited=summary["exploited"], total=summary["total"],
        metered=summary["metered"],
        mirror_only=summary["mirror_only"], errors=summary["errors"],
        target=escape(f'{summary["target_identity"]} @ {summary["target_host"]}'.strip(" @")),
        started=escape(summary["started_at"]),
        body="\n".join(cards))


def load_report(run_dir: Path) -> RunResult:
    """Rebuild a RunResult from <run_dir>/evidence.jsonl: last row per scenario gives verdict/steps/hits."""
    rows = EvidenceStore(Path(run_dir)).read()
    if not rows:
        raise ValueError("no evidence rows")
    last: dict[str, dict] = {}
    for r in rows:  # dicts keep first-seen scenario order
        last[r["scenario_id"]] = r
    return RunResult(rows[0]["run_id"], Path(run_dir), [
        ScenarioResult(sid, r["verdict"], [Canary("", t) for t in r["canary_hits"]], r["step_no"] + 1)
        for sid, r in last.items()])
