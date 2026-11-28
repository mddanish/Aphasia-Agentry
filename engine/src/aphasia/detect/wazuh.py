"""`aphasia detect`: correlate a run's evidence with Wazuh alerts, classify each step, write the
detection-gap report and the TUI view model.

Reads <run>/evidence.jsonl and either queries the Wazuh indexer (OpenSearch API) once or loads a
saved _search response (--from-file). Matching and classification follow SPEC §5. Credentials come
from aphasia.config ([wazuh] + APHASIA_WAZUH_PASSWORD); a password is never a CLI flag.
"""
import json
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from importlib import resources
from pathlib import Path

import httpx
import yaml

from aphasia import catalog as tax
from aphasia import config as cfg
from aphasia.evidence import EvidenceStore
from aphasia.report.render import (OWASP_NAMES, REMEDIATION, SEV_ORDER, _severity)
from aphasia.scenarios import DEFAULT_PATH as SCENARIOS, load_yaml

TELEMETRY_RULES = {"100200", "100201", "100205", "100206", "100207", "100300", "100301", "100302"}
# Engine verdict -> the TUI/run_view display vocabulary (demo_run.json / palette.VERDICT).
_DISPLAY_VERDICT = {"success": "proven", "metered": "metered", "mirror_only": "mirror_only"}


# ---------- gap fixes ----------
@lru_cache(maxsize=1)
def _gap_fixes() -> dict:
    return yaml.safe_load(resources.files("aphasia.data").joinpath("gap_fixes.yaml").read_text())


def _gap_fix(tool: str, event: str, kind: str) -> str:
    g = _gap_fixes()
    key = "missing" if kind == "log source" else "silent"
    if tool and tool in g.get("by_tool", {}):
        return g["by_tool"][tool].get(key, "")
    if event and event in g.get("by_event", {}):
        return g["by_event"][event].get(key, "")
    return g["default"][key]


# ---------- alert source ----------
def _query_body(start: str, end: str) -> dict:
    return {"size": 1000, "sort": [{"timestamp": "asc"}],
            "query": {"bool": {"filter": [
                {"terms": {"rule.groups": ["aphasia"]}},
                {"range": {"timestamp": {"gte": start, "lte": end}}}]}}}


def _fetch_alerts(c: cfg.Config, start: str, end: str, insecure: bool) -> list[dict]:
    url = c.wazuh.indexer_url.rstrip("/") + "/wazuh-alerts-4.x-*/_search"
    verify = False if (insecure or c.wazuh.insecure) else (c.wazuh.ca_cert or True)
    pw = c.secret(cfg.WAZUH_PASSWORD)
    r = httpx.post(url, json=_query_body(start, end), auth=(c.wazuh.user, pw),
                   verify=verify, timeout=20)
    r.raise_for_status()
    return _alerts_from(r.json())


def _alerts_from(resp: dict) -> list[dict]:
    out = []
    for h in resp.get("hits", {}).get("hits", []):
        s = h.get("_source", {})
        out.append({"ts": s.get("timestamp", ""), "rule": s.get("rule", {}), "data": s.get("data", {})})
    return out


# ---------- matching ----------
def _parse_ts(s: str) -> datetime | None:
    if not s:
        return None
    s = s.strip().replace("Z", "+00:00")
    # Wazuh timestamps look like 2026-12-04T10:15:04.511+0000
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(s.replace("+0000", "+00:00"), fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


def _match(step: dict, alerts: list[dict], before: int, after: int) -> list[dict]:
    """Alerts belonging to this evidence step. Strong: run_id+scenario+step; fallback: tool + time."""
    rid, sid, sn = str(step["run_id"]), str(step["scenario_id"]), str(step["step_no"])
    strong = [a for a in alerts if str(a["data"].get("run_id")) == rid
              and str(a["data"].get("scenario")) == sid and str(a["data"].get("step")) == sn]
    if strong:
        return strong
    tools = {tc.get("name") for tc in step.get("tool_calls", [])}
    if not tools:
        return []
    t0 = _parse_ts(step.get("ts", ""))
    win = []
    for a in alerts:
        if a["data"].get("tool") not in tools:
            continue
        at = _parse_ts(a["ts"])
        if t0 and at and (t0 - timedelta(minutes=before)) <= at <= (t0 + timedelta(seconds=after)):
            win.append(a)
        elif not t0:
            win.append(a)
    return win


def _classify(step: dict, matched: list[dict], min_level: int) -> tuple[str, dict | None]:
    """Return (result, best_alert). result ∈ blocked|detected|silent|missing|expected."""
    if step.get("verdict") == "blocked":
        return "blocked", None
    det = [a for a in matched if int(a["rule"].get("level", 0)) >= min_level
           and a["rule"].get("id") not in TELEMETRY_RULES]
    if det:
        best = max(det, key=lambda a: int(a["rule"].get("level", 0)))
        return "detected", best
    benign = not step.get("tool_calls") and not step.get("canary_hits")
    if matched:
        return ("expected" if benign else "silent"), (max(matched, key=lambda a: int(a["rule"].get("level", 0))))
    return ("expected" if benign else "missing"), None


# ---------- view model ----------
@lru_cache(maxsize=1)
def _catalog_by_scenario() -> dict:
    out: dict[str, list] = {}
    try:
        for t in tax.load().techniques:
            if t.scenario:
                out.setdefault(t.scenario, []).append(t)
    except Exception:
        return {}
    return out


def _short_ts(iso: str) -> str:
    d = _parse_ts(iso)
    return d.strftime("%H:%M:%S") if d else (iso[-8:] if iso else "")


def _action(step: dict) -> str:
    tcs = step.get("tool_calls", [])
    if tcs:
        return f"{tcs[0]['name']}({', '.join(f'{k}={v}' for k, v in (tcs[0].get('args') or {}).items())})"[:60]
    return (step.get("payload") or "inbound message")[:60]


_FLAG_KEYS = ("injection_in_tool_result", "honey_in_context", "honey_in_reply", "desc_changed")


def _load_exchanges(proxy_dir: Path | None) -> list[dict]:
    """Build run_view.exchanges from <proxy_dir>/proxy.jsonl (recorder llm_exchange lines)."""
    if not proxy_dir:
        return []
    pj = Path(proxy_dir) / "proxy.jsonl"
    if not pj.exists():
        return []
    out, n = [], 0
    for line in pj.read_text().splitlines():
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if e.get("event") != "llm_exchange":
            continue
        n += 1
        out.append({
            "no": n, "ts": _short_ts(e.get("ts", "")), "scenario": e.get("scenario", ""),
            "step": e.get("step", ""), "session": e.get("session", ""), "model": e.get("model", ""),
            "latency_ms": e.get("latency_ms", 0),
            "flags": [k for k in _FLAG_KEYS if e.get(k)],
            "messages": e.get("messages", []), "tools": e.get("tools", []),
            "tool_calls": e.get("tool_calls", []), "reply": e.get("reply", ""),
        })
    return out


def build_view(run_dir: Path, alerts: list[dict], min_level: int, before: int, after: int,
               siem: str = "wazuh", proxy_dir: Path | None = None) -> dict:
    rows = EvidenceStore(run_dir).read()
    meta = {s.id: s for s in load_yaml(SCENARIOS)}
    catalog = _catalog_by_scenario()

    # per-step results
    steps_view, by_scenario_rows = [], {}
    for r in rows:
        matched = _match(r, alerts, before, after)
        result, alert = _classify(r, matched, min_level)
        tool = r["tool_calls"][0]["name"] if r.get("tool_calls") else "-"
        telemetry = bool(matched)
        step_view = {
            "scenario": r["scenario_id"], "no": r["step_no"] + 1, "ts": _short_ts(r.get("ts", "")),
            "action": _action(r), "tool": tool, "blocked": r.get("verdict") == "blocked",
            "telemetry": telemetry,
            "alert": ({"rule": alert["rule"].get("id"), "level": int(alert["rule"].get("level", 0)),
                       "desc": alert["rule"].get("description", "")} if alert else None),
            "result": result,
        }
        if alert and str(alert["rule"].get("id", "")).startswith("1003"):
            step_view["gateway"] = alert["rule"].get("description", "")
        steps_view.append(step_view)
        by_scenario_rows.setdefault(r["scenario_id"], []).append(r)

    # per-scenario verdicts (last row wins; success if any success row)
    scenarios_view, verdict_of = [], {}
    for sid, srows in by_scenario_rows.items():
        verdict = "success" if any(x["verdict"] == "success" for x in srows) else srows[-1]["verdict"]
        verdict_of[sid] = verdict
        m = meta.get(sid)
        cat = category = (m.category if m else "")
        sev = _severity(verdict, cat)
        proof_row = next((x for x in srows if x["verdict"] == "success"), srows[-1])
        hits = proof_row.get("canary_hits") or []
        techs = catalog.get(sid, [])
        scenarios_view.append({
            "id": sid, "title": (m.category if m else sid),
            "owasp": (m.owasp if m else ""), "atlas": (m.atlas if m else ""),
            "aatmf": (techs[0].sources.get("aatmf", "") if techs else ""),
            "severity": sev, "verdict": _DISPLAY_VERDICT.get(verdict, "not_proven"),
            "proof": (f"canary {', '.join(hits)} in evidence" if hits else proof_row.get("verdict", "")),
            "fix": REMEDIATION.get(category, ""),
        })

    # gaps: silent/missing steps of a proven scenario, ranked by severity then missing-before-silent
    gaps = []
    for sv in steps_view:
        if sv["result"] not in ("silent", "missing"):
            continue
        sid = sv["scenario"]
        if verdict_of.get(sid) not in ("success", "metered", "mirror_only"):
            continue
        kind = "log source" if sv["result"] == "missing" else "rule"
        sev = _severity(verdict_of[sid], meta[sid].category if sid in meta else "")
        gaps.append({"severity": sev, "kind": kind,
                     "covers": f"{sid} #{sv['no']}", "title": _gap_title(sv, kind),
                     "fix": _gap_fix(sv["tool"] if sv["tool"] != "-" else "", "", kind),
                     "_order": (SEV_ORDER.get(sev, 9), 0 if sv["result"] == "missing" else 1)})
    gaps.sort(key=lambda g: g.pop("_order"))
    for i, g in enumerate(gaps, 1):
        g["rank"] = i
    gaps = [{"rank": g["rank"], "title": g["title"], "kind": g["kind"], "severity": g["severity"],
             "covers": g["covers"], "fix": g["fix"]} for g in gaps]

    exchanges = _load_exchanges(proxy_dir)
    any_row = rows[0] if rows else {}
    started = _short_ts(any_row.get("ts", ""))
    return {
        "run_id": any_row.get("run_id", run_dir.name), "started": started,
        "target": f"{any_row.get('target_identity', '')} · {any_row.get('target_host', '')}".strip(" ·"),
        "mode": "seed", "duration_min": 0, "siem": siem,
        "deploy_mode": "proxy" if exchanges else "direct", "exchanges": exchanges,
        "scenarios": scenarios_view, "steps": steps_view, "gaps": gaps,
    }


def _gap_title(sv: dict, kind: str) -> str:
    if kind == "log source":
        return f"No log source for {sv['tool'] if sv['tool'] != '-' else 'this step'} ({sv['scenario']})"
    return f"{sv['action'][:40]} not detected ({sv['scenario']})"


# ---------- entry point ----------
def detect(run_dir: Path, from_file: Path | None = None, insecure: bool = False,
           window_before: int = 5, window_after: int = 90, min_level: int = 7,
           proxy_dir: Path | None = None) -> dict:
    run_dir = Path(run_dir)
    rows = EvidenceStore(run_dir).read()
    if not rows:
        raise ValueError(f"no evidence rows in {run_dir}")

    if from_file:
        alerts = _alerts_from(json.loads(Path(from_file).read_text()))
        siem = "offline"
    else:
        c = cfg.load()
        if not c.wazuh.indexer_url:
            raise ValueError("no Wazuh indexer URL; set [wazuh] in config or run `aphasia setup`, "
                             "or pass --from-file for offline mode")
        ts = [_parse_ts(r.get("ts", "")) for r in rows if _parse_ts(r.get("ts", ""))]
        lo = (min(ts) - timedelta(minutes=window_before)) if ts else datetime.now(timezone.utc)
        hi = (max(ts) + timedelta(seconds=window_after)) if ts else datetime.now(timezone.utc)
        alerts = _fetch_alerts(c, lo.isoformat(), hi.isoformat(), insecure)
        siem = f"wazuh · {c.wazuh.indexer_url}"

    view = build_view(run_dir, alerts, min_level, window_before, window_after, siem=siem,
                      proxy_dir=proxy_dir)

    detections = [{"scenario": s["scenario"], "step_no": s["no"], "result": s["result"],
                   "alerts": ([{"rule_id": s["alert"]["rule"], "level": s["alert"]["level"],
                                "description": s["alert"]["desc"]}] if s["alert"] else [])}
                  for s in view["steps"]]
    (run_dir / "detections.json").write_text(json.dumps(detections, indent=2))
    (run_dir / "run_view.json").write_text(json.dumps(view, indent=2))
    return view
