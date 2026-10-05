"""aphasia CLI: list | payloads | run | report."""
import argparse
import os
import sys
import time
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

try:
    __version__ = version("aphasia-agentry")
except PackageNotFoundError:  # running from source without an install
    __version__ = "0+unknown"

from aphasia.connectors import ConnectorError, HttpConnector, McpConnector
from aphasia.payloads import load_payloads
from aphasia.providers import LiteLLMProvider, ProviderError
from aphasia.report import load_report, write_report
from aphasia.run import run_all
from aphasia.scenarios import load_yaml

SCENARIOS = Path(__file__).resolve().parents[3] / "scenarios.yaml"  # oss/scenarios.yaml
PAYLOADS = Path(__file__).resolve().parents[3] / "payloads.yaml"    # oss/payloads.yaml
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


def _run(a) -> int:
    scs = load_yaml(SCENARIOS)
    if a.scenario:
        known = {s.id for s in scs}
        bad = [s for s in a.scenario if s not in known]
        if bad:
            print(f"error: unknown scenario(s): {', '.join(bad)}", file=sys.stderr)
            return 2
        scs = [s for s in scs if s.id in a.scenario]
    payloads = load_payloads(PAYLOADS) if a.mode in ("seed", "hybrid") else {}
    try:
        # seed mode needs no LLM; adaptive/hybrid build the litellm provider
        provider = None if a.mode == "seed" else LiteLLMProvider(model=a.model, api_base=a.api_base)
        connector = _connector(a.target)
        # run_id is generated inside run_all, so default out is a fresh timestamped dir
        out = Path(a.out) if a.out else Path("runs") / time.strftime("%Y%m%dT%H%M%S")
        res = run_all(scs, connector, provider, out, a.max_steps, mode=a.mode, payloads=payloads)
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
    r.add_argument("--mode", default="hybrid", choices=["seed", "adaptive", "hybrid"],
                   help="seed = curated payloads only (no LLM); adaptive = LLM only; "
                        "hybrid = seeds first, then the LLM adapts [default: hybrid]")
    r.add_argument("--model", default="ollama/llama3.2:1b", metavar="MODEL",
                   help="litellm model string for the attacker, e.g. ollama/llama3.2:1b, "
                        "gpt-4o-mini, anthropic/claude-3-5-haiku, groq/llama-3.1-8b-instant "
                        "[default: ollama/llama3.2:1b]")
    r.add_argument("--api-base", default=os.environ.get("OLLAMA_API_BASE") or os.environ.get("OLLAMA_HOST"),
                   metavar="URL", help="base URL for a self-hosted backend (e.g. your Ollama/vLLM "
                        "server); unused in seed mode. Keys come from litellm env vars")
    r.add_argument("--max-steps", type=int, default=6, metavar="N",
                   help="max attacker steps per scenario [default: 6]")
    r.add_argument("--out", metavar="DIR",
                   help="output dir for report + evidence [default: runs/<timestamp>]")

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
