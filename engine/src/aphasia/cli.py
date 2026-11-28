"""aphasia CLI: list | payloads | run | report."""
import argparse
import json
import os
import sys
import time
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

try:
    __version__ = version("aphasia-agentry")
except PackageNotFoundError:  # running from source without an install
    __version__ = "0+unknown"

from aphasia import catalog, config
from aphasia.connectors import ConnectorError, HttpConnector, McpConnector
from aphasia.payloads import DEFAULT_PATH as PAYLOADS, load_payloads
from aphasia.providers import LiteLLMProvider, ProviderError
from aphasia.report import load_report, write_report
from aphasia.run import run_all
from aphasia.scenarios import DEFAULT_PATH as SCENARIOS, load_yaml

FIXTURE = "http://127.0.0.1:8000"


def exit_code(run_result) -> int:
    return 1 if any(r.verdict in ("success", "metered") for r in run_result.results) else 0


def _table(headers: list[str], rows: list[list]) -> str:
    cells = [[str(c) for c in r] for r in rows]
    w = [len(h) for h in headers]
    for r in cells:
        for i, c in enumerate(r):
            w[i] = max(w[i], len(c))

    def rule(left, mid, right):
        return left + mid.join("─" * (x + 2) for x in w) + right

    def line(vals):
        return "│" + "│".join(f" {v:<{w[i]}} " for i, v in enumerate(vals)) + "│"

    out = [rule("┌", "┬", "┐"), line(headers), rule("├", "┼", "┤")]
    out += [line(r) for r in cells]
    out.append(rule("└", "┴", "┘"))
    return "\n".join(out)


def _connector(target: str):
    if target == "fixture":
        return HttpConnector(FIXTURE + "/chat", plant_url=FIXTURE + "/seed")
    if target.startswith(("http://", "https://")):
        return HttpConnector(target)
    return McpConnector(target)


def _attacker(a) -> LiteLLMProvider:
    """Build the ATTACKER LLM from flags > APHASIA_ATTACKER_* env > config > legacy defaults."""
    cfg = config.load()
    bad = [p for p in config.problems(cfg) if p.startswith(("attacker", "environment"))]
    if bad:
        raise ProviderError("; ".join(bad))
    model = a.model or cfg.attacker.model or "ollama/llama3.2:1b"
    base = (a.api_base or cfg.attacker.api_base
            or os.environ.get("OLLAMA_API_BASE") or os.environ.get("OLLAMA_HOST") or None)
    if cfg.proxy.enabled and config.same_endpoint(base or "", cfg.proxy.listen):
        raise ProviderError("attacker LLM base URL points at the Aphasia proxy; use a different --api-base")
    key = cfg.secret(config.ATTACKER_KEY) or None
    if key is None and config.needs_key(model, base or ""):
        if cfg.proxy.enabled:  # proxy mode: shared provider vars would mix attacker and agent traffic
            raise ProviderError(f"{config.ATTACKER_KEY} is not set (required for {model} when the proxy "
                                "is enabled; shared provider variables are not used)")
        print(f"warning: {config.ATTACKER_KEY} not set; litellm will use its provider env vars for {model}",
              file=sys.stderr)
    return LiteLLMProvider(model=model, api_base=base, api_key=key)


def _proxy(a) -> int:
    from aphasia.proxy import control
    c = config.load()
    if a.proxy_cmd == "status":
        st = control.status(c)
        print(json.dumps(st, indent=2))
        return 0 if st.get("running") else 1
    if a.proxy_cmd == "stop":
        print(json.dumps(control.stop(c), indent=2))
        return 0
    try:
        s = control.start(c, provider_model=a.provider_model or "", api_base=a.api_base or "",
                          alias=a.alias or "", listen=a.listen or "", full=a.full)
    except (ValueError, RuntimeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    print("proxy up — point the agent under test at:")
    print(f"  OpenAI-compatible:    base_url={s['base_url']}   api_key={s['api_key']}   model={s['model']}")
    print(f"  Anthropic-compatible: ANTHROPIC_BASE_URL={s['anthropic_base']}   ANTHROPIC_API_KEY={s['api_key']}")
    print(f"  pid {s['pid']} · logs {s['dir']}/proxy.jsonl · stop with `aphasia proxy stop`")
    return 0


def _detect(a) -> int:
    from aphasia.detect import detect
    try:
        view = detect(Path(a.run), Path(a.from_file) if a.from_file else None, insecure=a.insecure,
                      window_before=a.window_before, window_after=a.window_after, min_level=a.min_level,
                      proxy_dir=Path(a.proxy) if getattr(a, "proxy", None) else None)
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except Exception as e:  # httpx and friends raise many types; surface cleanly
        print(f"error: Wazuh query failed: {e}", file=sys.stderr)
        return 2
    det = sum(1 for s in view["steps"] if s["result"] == "detected")
    sil = sum(1 for s in view["steps"] if s["result"] == "silent")
    mis = sum(1 for s in view["steps"] if s["result"] == "missing")
    print(f"detect {view['run_id']}: {det} detected · {sil} silent · {mis} no-telemetry · "
          f"{len(view['gaps'])} gap(s) — wrote {a.run}/run_view.json, detections.json")
    return 0


def _catalog(a) -> int:
    cat = catalog.load()
    cats = [cat.category(a.category)] if a.category and cat.category(a.category) else cat.categories
    if a.category and not cat.category(a.category):
        print(f"error: unknown category '{a.category}'", file=sys.stderr)
        return 2
    runnable = {s.id for s in load_yaml(SCENARIOS)}
    for c in cats:
        techs = [t for t in cat.in_category(c.id) if not a.proxy_better or t.proxy_better]
        if not techs:
            continue
        print(f"\n[{c.id}] {c.name}  (proxy: {c.proxy_hint})")
        rows = []
        for t in techs:
            run = "yes" if t.scenario in runnable else ("none" if t.testable == "none" else "todo")
            rows.append([t.id, t.name[:38], t.owasp, "proxy+" if t.proxy_better else "",
                         t.testable, t.scenario or "-", run])
        print(_table(["ID", "Technique", "OWASP", "", "Test", "Scenario", "Runs"], rows))
    total = len(cat.techniques)
    runs = sum(1 for t in cat.techniques if t.scenario in runnable)
    print(f"\n{total} techniques · {runs} runnable now · "
          f"{sum(1 for t in cat.techniques if t.proxy_better)} clearer in proxy mode · "
          f"{sum(1 for t in cat.techniques if t.testable == 'none')} reference-only")
    print("Sources: AATMF v3 (CC BY-SA 4.0) · Arcanum PI Taxonomy (CC BY 4.0) · ZeroLeaks (FSL-1.1). "
          "See docs/CREDITS.md.", file=sys.stderr)
    return 0


def _setup(a) -> int:
    from aphasia.tui.app import run_tui
    return run_tui(setup=True, setup_only=True)


def _config_show(a) -> int:
    cfg = config.load()
    print(json.dumps(config.redacted(cfg), indent=2))
    for p in config.problems(cfg):
        print(f"error: {p}", file=sys.stderr)
    for w in config.warnings(cfg):
        print(f"warning: {w}", file=sys.stderr)
    print(f"config dir: {config.home()}", file=sys.stderr)
    return 2 if config.problems(cfg) else 0


def _run(a) -> int:
    scs = load_yaml(SCENARIOS)
    if getattr(a, "category", None) and a.scenario:
        print("error: use --category or --scenario, not both", file=sys.stderr)
        return 2
    if getattr(a, "category", None):
        picked, notes = catalog.select(a.category, [s.id for s in scs])
        for n in notes:
            print(f"note: {n}", file=sys.stderr)
        if not picked:
            return 2
        scs = [s for s in scs if s.id in picked]
    elif a.scenario:
        known = {s.id for s in scs}
        bad = [s for s in a.scenario if s not in known]
        if bad:
            print(f"error: unknown scenario(s): {', '.join(bad)}", file=sys.stderr)
            return 2
        scs = [s for s in scs if s.id in a.scenario]
    payloads = load_payloads(PAYLOADS) if a.mode in ("seed", "hybrid") else {}
    try:
        # seed mode needs no LLM; adaptive/hybrid build the litellm provider
        provider = None if a.mode == "seed" else _attacker(a)
        connector = _connector(a.target)
        # run_id is generated inside run_all, so default out is a fresh timestamped dir
        out = Path(a.out) if a.out else Path("runs") / time.strftime("%Y%m%dT%H%M%S")
        pdir = Path(a.proxy) if getattr(a, "proxy", None) else None
        res = run_all(scs, connector, provider, out, a.max_steps, mode=a.mode, payloads=payloads,
                      proxy_dir=pdir)
    except (ProviderError, ConnectorError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    write_report(res, out)
    errs = [r.scenario_id for r in res.results if r.verdict == "error"]
    if errs:  # run_all records provider/connector failures as 'error' verdicts
        print(f"error: target/provider failure in scenario(s): {', '.join(errs)} "
              f"(see {out}/evidence.jsonl)", file=sys.stderr)
    print(f"run {res.run_id}: report in {out}")
    return exit_code(res) or (2 if errs else 0)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="aphasia",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Aphasia Agentry — Agentic BAS for AI agents and MCP servers.\n"
                    "Drives an attacker (seed payloads and/or an LLM) against a target, proves\n"
                    "impact with per-run canaries, and reports mapped to the OWASP LLM Top 10.",
        epilog="Examples:\n"
               "  aphasia list                       Show scenarios (OWASP LLM Top 10)\n"
               "  aphasia payloads                   Show the seed-payload library\n"
               "  aphasia run --mode seed            Reproducible, no LLM, vs the fixture\n"
               "  aphasia run --model gpt-4o-mini    Adaptive LLM attacker (any litellm model)\n"
               "  aphasia run --model ollama/llama3.2:1b --api-base http://host:11434   Local Ollama\n"
               "  aphasia run --target http://host:8000/chat      Your own HTTP agent\n"
               "  aphasia report --run-dir runs/<id>  Re-render report from evidence\n\n"
               "The bundled fixture is INTENTIONALLY VULNERABLE — run it on localhost only.")
    p.add_argument("--version", action="version", version=f"aphasia {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True, metavar="<command>")

    sub.add_parser("list", help="list attack scenarios and their OWASP/ATLAS mapping",
                   description="Print the scenario catalogue (OWASP LLM Top 10) with ATLAS ids, "
                               "delivery channel and seed-payload counts.")
    sub.add_parser("payloads", help="show the curated seed-payload library counts",
                   description="Print how many seed injection payloads ship per scenario.")

    r = sub.add_parser("run", help="run attack scenarios against a target",
                       description="Run scenarios against a target and write a report + evidence log.")
    r.add_argument("--target", default="fixture", metavar="TARGET",
                   help="'fixture' (bundled vulnerable agent on 127.0.0.1:8000), an http(s):// "
                        "chat URL, or an MCP endpoint [default: fixture]")
    r.add_argument("--scenario", action="append", metavar="ID",
                   help="run only this scenario id (repeatable) [default: all]")
    r.add_argument("--category", metavar="CAT",
                   help="run a taxonomy category instead: all, or one of "
                        "prompt_injection, evasion, extraction, exfiltration, tool_mcp, rag_memory, "
                        "multi_turn, excessive_agency, multimodal, availability, misinformation "
                        "(see `aphasia catalog`). Mutually exclusive with --scenario")
    r.add_argument("--mode", default="hybrid", choices=["seed", "adaptive", "hybrid"],
                   help="seed = curated payloads only (no LLM); adaptive = LLM only; "
                        "hybrid = seeds first, then the LLM adapts [default: hybrid]")
    r.add_argument("--model", default=None, metavar="MODEL",
                   help="ATTACKER LLM (Aphasia's own, not the proxy upstream): litellm model string, "
                        "e.g. ollama/llama3.2:1b, gpt-4o-mini, anthropic/claude-3-5-haiku "
                        "[default: config [attacker].model, else ollama/llama3.2:1b]")
    r.add_argument("--api-base", default=None, metavar="URL",
                   help="attacker LLM base URL for a self-hosted backend (Ollama/vLLM); unused in seed "
                        "mode [default: config [attacker].api_base, else OLLAMA_API_BASE/OLLAMA_HOST]. "
                        "Key: APHASIA_ATTACKER_API_KEY (env or secrets.env), else litellm env vars")
    r.add_argument("--max-steps", type=int, default=6, metavar="N",
                   help="max attacker steps per scenario [default: 6]")
    r.add_argument("--out", metavar="DIR",
                   help="output dir for report + evidence [default: runs/<timestamp>]")
    r.add_argument("--proxy", metavar="DIR",
                   help="proxy mode: write run context into this proxy dir (e.g. runs/proxy) so the "
                        "gateway recorder tags each LLM exchange")

    cat = sub.add_parser("catalog", help="list the merged technique taxonomy (AATMF + Arcanum + ZeroLeaks)",
                         description="Print techniques by category, which scenario tests each, and which "
                                     "are clearer in proxy mode. Reference metadata; run with --category.")
    cat.add_argument("--category", metavar="CAT", help="show only this category")
    cat.add_argument("--proxy-better", action="store_true", help="show only techniques clearer in proxy mode")
    sub.add_parser("setup", help="first-run setup in the TUI (target, attacker LLM, proxy, Wazuh)",
                   description="Open the TUI setup wizard and write ~/.config/aphasia/config.toml "
                               "and secrets.env (0600).")
    sub.add_parser("config", help="show the current configuration (secrets redacted) and checks",
                   description="Print config with secrets as set/not set, then errors and warnings.")
    tu = sub.add_parser("tui", help="open the terminal UI",
                        description="Open the TUI. First run opens setup automatically.")
    tu.add_argument("--run", metavar="DIR", help="run directory with run_view.json")
    tu.add_argument("--demo", action="store_true", help="bundled demo data, skip setup")

    px = sub.add_parser("proxy", help="run the LLM gateway (proxy mode) in its own env",
                        description="start/status/stop the LiteLLM gateway with the Aphasia recorder. "
                                    "Uses only [upstream] + APHASIA_UPSTREAM_API_KEY.")
    pxs = px.add_subparsers(dest="proxy_cmd", required=True, metavar="<action>")
    ps = pxs.add_parser("start", help="start the gateway and print the agent settings")
    ps.add_argument("--provider-model", metavar="MODEL", help="upstream model, e.g. ollama_chat/qwen2.5:7b-instruct")
    ps.add_argument("--api-base", metavar="URL", help="upstream base URL (local/self-hosted providers)")
    ps.add_argument("--alias", metavar="NAME", help="model name the agent asks for [agent-model]")
    ps.add_argument("--listen", metavar="HOST:PORT", help="bind address [127.0.0.1:4000]")
    ps.add_argument("--full", action="store_true", help="log full text (no 2000-char clipping)")
    pxs.add_parser("status", help="is the gateway running?")
    pxs.add_parser("stop", help="stop the gateway")

    dt = sub.add_parser("detect", help="correlate a run's evidence with Wazuh alerts (detection gaps)",
                        description="For each attack step, check whether Wazuh detected it; write "
                                    "detections.json and run_view.json for the TUI.")
    dt.add_argument("--run", required=True, metavar="DIR", help="a run directory with evidence.jsonl")
    dt.add_argument("--from-file", metavar="PATH", help="offline: a saved Wazuh _search response JSON")
    dt.add_argument("--insecure", action="store_true", help="skip TLS verification (lab only)")
    dt.add_argument("--window-before", type=int, default=5, metavar="MIN", help="minutes before a step [5]")
    dt.add_argument("--window-after", type=int, default=90, metavar="SEC", help="seconds after a step [90]")
    dt.add_argument("--min-level", type=int, default=7, metavar="N", help="min Wazuh level counted as detected [7]")
    dt.add_argument("--proxy", metavar="DIR", help="proxy dir (reads proxy.jsonl into the TUI Trace view)")

    rp = sub.add_parser("report", help="re-render a report from a past run's evidence",
                        description="Rebuild report.html/report.json from <run-dir>/evidence.jsonl.")
    rp.add_argument("--run-dir", required=True, metavar="DIR", help="a previous run's output dir")
    a = p.parse_args(argv)
    if a.cmd == "list":
        scs = load_yaml(SCENARIOS)
        lib = load_payloads(PAYLOADS)
        rows = [[s.id, s.owasp, s.atlas or "-", s.channel, len(lib.get(s.id, [])), s.category]
                for s in scs]
        print(_table(["Scenario", "OWASP", "ATLAS", "Channel", "Seeds", "Category"], rows))
        print(f"{len(scs)} scenarios · OWASP LLM Top 10 · "
              f"{sum(len(v) for v in lib.values())} seed payloads")
        return 0
    if a.cmd == "payloads":
        scs = load_yaml(SCENARIOS)
        lib = load_payloads(PAYLOADS)
        rows = [[s.id, s.owasp, len(lib.get(s.id, []))] for s in scs]
        print(_table(["Scenario", "OWASP", "Seeds"], rows))
        print(f"Total: {sum(len(v) for v in lib.values())} seed payloads "
              f"across {len(scs)} scenarios")
        return 0
    if a.cmd == "catalog":
        return _catalog(a)
    if a.cmd == "detect":
        return _detect(a)
    if a.cmd == "proxy":
        return _proxy(a)
    if a.cmd == "setup":
        return _setup(a)
    if a.cmd == "config":
        return _config_show(a)
    if a.cmd == "tui":
        from aphasia.tui.app import run_tui
        if a.run and not (Path(a.run) / "run_view.json").exists():
            print(f"error: {a.run}/run_view.json not found; run `aphasia detect --run {a.run}` first",
                  file=sys.stderr)
            return 2
        return run_tui(a.run, demo=a.demo)
    if a.cmd == "report":
        try:
            write_report(load_report(Path(a.run_dir)), Path(a.run_dir))
        except (OSError, KeyError, ValueError) as e:
            print(f"error: cannot rebuild report from evidence.jsonl in {a.run_dir}: {e}", file=sys.stderr)
            return 2
        return 0
    return _run(a)


if __name__ == "__main__":
    sys.exit(main())
