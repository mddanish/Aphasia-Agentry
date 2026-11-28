# Aphasia Agentry

Agentic BAS for AI agents and MCP servers: attack a target, prove impact with per-run canaries,
then check whether the SOC (Wazuh) detected each step. Python 3.11+, uv, Apache-2.0.

Current work: v0.2 = two modes (direct black box, proxy LLM gateway) + TUI + Wazuh defender loop,
for the BSides Kolkata live demo (4–5 Dec 2026).
Specs: `docs/build/SPEC.md` (contracts), `docs/build/TUI_STYLE.md` (look), `docs/build/PLAN.md` (phases),
`docs/build/WAZUH.md` (lab SIEM). Read the relevant section before changing code.

## Layout

- `engine/src/aphasia/` — package: `cli.py`, `run.py`, `attacker.py`, `connectors/`, `canary/`, `evidence/`, `report/`
- `engine/src/aphasia/config.py` — instance config, the two LLMs, secrets, checks (done)
- `engine/src/aphasia/catalog.py` + `data/catalog.yaml` — merged technique taxonomy + scan selection (done)
- `engine/src/aphasia/tui/` — Textual TUI (starter: layout and theme are the visual baseline; `setup.py` wizard done)
- `engine/src/aphasia/detect/` — Wazuh correlation (`aphasia detect`, done)
- `engine/src/aphasia/proxy/` — proxy mode: `recorder.py` (done) + `aphasia proxy` (to build)
- fixture telemetry: `fixture/agent/app.py` writes JSON lines to `$APHASIA_LOG`; engine sends `X-Aphasia-*` headers (done)
- `deploy/proxy/` — LiteLLM config template
- `fixture/` — deliberately vulnerable agent (Flask) + MCP server, Docker, localhost only
- `deploy/wazuh/` — rules 1002xx (direct) and 1003xx (proxy), CDB lists, samples, compose override

## Commands

```
cd engine
uv sync                                   # install (textual, httpx, litellm, mcp, pyyaml)
uv run python -m pytest -q                # all tests (test_live.py needs a fixture + Ollama)
uv run aphasia run --mode seed            # attack the fixture, writes runs/<id>/
uv run aphasia tui --demo                 # TUI on bundled demo data
uv run aphasia setup                      # first-run setup wizard (also opens on first `aphasia tui`)
uv run aphasia config                     # show config, secrets redacted, plus checks
uvx --from "litellm[proxy]==1.111.0" litellm --config runs/proxy/config.yaml   # proxy, own env
docker compose -f ../fixture/docker-compose.yml up -d
```

## Rules

- Fixture stays intentionally vulnerable but sandbox-inert: no exec, no outbound network, no
  attacker-chosen file paths. Ports bind 127.0.0.1 only. Never change that.
- Verdicts are canary/mirror evidence only. Never add an LLM-judge verdict.
- Do not change existing scenario IDs, evidence's 12 required keys, or CLI flags. Add, don't break.
- Secrets (Wazuh password, API keys) come from env vars only. Never a CLI flag, never logged, never committed.
- Two LLMs, never mixed: ATTACKER (`[attacker]`, `APHASIA_ATTACKER_API_KEY`, Aphasia's own, plans
  attacks, never routed via the proxy) and UPSTREAM (`[upstream]`, `APHASIA_UPSTREAM_API_KEY`, proxy mode,
  serves the agent under test). Read both only through `aphasia.config`; never use generic
  `OPENAI_API_KEY`/`OPENAI_BASE_URL` for either. Keep `config.problems()` checks passing.
- Config lives in `$APHASIA_HOME` (default ~/.config/aphasia): config.toml + secrets.env (0600).
  Tests must never touch the real one (tests/conftest.py isolates it).
- Never add `litellm[proxy]` to pyproject: it pins rich<14, Textual needs rich>=14.2. The proxy runs
  only via uvx in its own env. The recorder may import only stdlib + litellm.
- Proxy binds 127.0.0.1 by default. Prompts pass through it: proxy logs live under runs/ (gitignored).
- New runtime dependencies need a reason; prefer what is already in pyproject (httpx, rich/textual).
- Every new module gets tests. Keep `uv run python -m pytest -q` green before each commit.
- TUI: follow `docs/build/TUI_STYLE.md`. Build Rich text with `palette.styled()`, not `Text(x, style=)`.
- Visual reference is Darkmoon (AGPL-3.0). Copy the look only; never copy its code or images.
- Technique catalog (`data/catalog.yaml`) is deduplicated reference metadata: one source taxonomy id
  maps to one Aphasia technique (a test enforces it); `testable: none` entries are never run. Keep
  `docs/build/CREDITS.md` and the per-entry `sources`. Add a scenario, then point a technique at it;
  never invent a `scenario` that is not registered.
- Proxy guidance is advisory: `--category` and selection run in direct mode too. Highlight
  `proxy_better`, never block direct mode.
- Wazuh rules: test each change with `wazuh-logtest`; first matching sibling wins, so order matters.
  Do not add rules for the deliberate demo gaps listed in `deploy/wazuh/aphasia_rules.xml`.
