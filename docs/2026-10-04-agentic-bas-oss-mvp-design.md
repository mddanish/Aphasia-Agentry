# Agentic BAS — Open-Source MVP Design

**Date:** 2026-10-04
**Author:** Mohammed Danish Amber
**Status:** Design, pending review

## Purpose and goal

Build the first open-source release of Agentic BAS: a breach-and-attack-simulation
engine for deployed AI agents and MCP servers. The release target is **community
reach** — a tool a security researcher or agent builder can clone and run in about
five minutes, get a canary-proven finding, and want to share.

Success for this release: a user runs one command against a bundled vulnerable
target (or their own agent, or an external Damn Vulnerable MCP server) and gets a
finding proven by a canary hit, backed by a replayable evidence log and a shareable
HTML report.

This is the open-source wedge of a larger open-core product. The commercial build
(SIEM/EDR detection validation, exposure dashboard, multi-tenancy) comes later and
reuses this engine as a library. This spec covers the open-source release only.

## Non-goals (explicitly out of this release)

- SIEM/EDR detection validation (the commercial differentiator; Wazuh Community
  Edition is the planned backend, built in a later phase).
- Agent Exposure Score beyond a basic value; no trend or dashboard.
- Automatic discovery of agents/tools across clouds.
- Web UI. The shareable artifact is a static HTML report from the CLI.
- Scheduling, continuous mode, CI gating beyond a meaningful exit code.
- Multi-tenancy, SSO, on-prem packaging.
- Advanced / weaponised scenarios in the public set (gated for misuse reasons).
- A database for runs (one local run writes one JSONL file).
- Sandbox-execute tool mirror tier (record-only only; sandbox-execute is Phase 2).

## Key decisions

| Decision | Choice | Reason |
| --- | --- | --- |
| Build order | Open source first | Goal is community reach within ~3 months |
| Language / tooling | Python 3, `uv` | MCP Python SDK; target agents and peer tools are Python |
| Licence | Apache-2.0 | Patent + trademark cover for an open-core play; reusable |
| Bundled target | Thin canary fixture (not a CTF range) | A BAS fixture our engine drives, not another human CTF |
| External target | Support Damn Vulnerable MCP server (DVMCP) as a `--target` | It speaks MCP; no DVMCP-specific code needed |
| Attacker LLM | Ollama default, one provider seam | Zero-cost offline default; frontier model one env var away |
| Ollama host | Configurable base URL (`OLLAMA_HOST`) | Testing uses a remote Ollama server, not localhost |
| Verification | Canary hit or tool-mirror capture; never an LLM judge | Proof, not judgement — the product's core discipline |
| Repo shape | Monorepo; publishable code under `oss/` | Clean publish boundary; keeps private strategy docs out |

## Repository layout

```
Agentic-BAS/                 # private monorepo root
├── Artifacts/               # strategy, competitor teardown, attack-library xlsx — PRIVATE, never published
├── oss/                     # publishable open-source subtree (Apache-2.0)
│   ├── engine/              # installable package
│   │   ├── pyproject.toml
│   │   ├── src/aphasia/
│   │   │   ├── cli.py                # `aphasia` entry point
│   │   │   ├── run.py                # orchestrates one run; owns caps + kill switch
│   │   │   ├── attacker.py           # attacker agent: plans/adapts multi-step chains
│   │   │   ├── providers/
│   │   │   │   ├── base.py           # Provider interface
│   │   │   │   └── ollama.py         # default impl (configurable base URL)
│   │   │   ├── connectors/
│   │   │   │   ├── base.py           # TargetConnector interface
│   │   │   │   ├── http.py           # generic HTTP agent
│   │   │   │   └── mcp.py            # MCP client — drives fixture AND DVMCP
│   │   │   ├── scenarios/
│   │   │   │   ├── __init__.py       # register() + registry
│   │   │   │   └── *.py              # basic scenarios, one file each
│   │   │   ├── canary/
│   │   │   │   ├── tokens.py         # per-run HMAC tokens
│   │   │   │   └── mirror.py         # record-only tool mirror
│   │   │   ├── evidence/store.py     # append-only JSONL per run
│   │   │   ├── score.py              # basic Agent Exposure Score
│   │   │   └── report/
│   │   │       ├── render.py
│   │   │       └── template.html
│   │   └── tests/
│   ├── fixture/             # thin vulnerable canary target (docker-only, never on PyPI)
│   │   ├── docker-compose.yml
│   │   ├── agent/           # deliberately-vulnerable HTTP agent, canary-seeded
│   │   └── mcp/             # deliberately-vulnerable MCP server, canary-seeded
│   ├── docs/
│   │   ├── quickstart.md
│   │   └── scenarios.md
│   ├── scenarios.yaml       # scenario metadata, generated from the attack-library xlsx
│   ├── LICENSE              # Apache-2.0
│   ├── NOTICE
│   ├── README.md
│   └── CONTRIBUTING.md
└── README.md               # monorepo map: private vs public, how commercial reuses oss/
```

Notes:
- `src/` layout for honest imports and clean packaging.
- `engine/` (installable) and `fixture/` (Docker-only) are split so attack code and
  target code never mix. The engine never imports fixture code; it reaches the
  fixture only over HTTP/MCP.
- The attack-library spreadsheet in `Artifacts/` stays the human source of truth for
  scenario metadata. `scenarios.yaml` is generated from it and is what the code reads,
  so metadata lives in one place.
- Apache `LICENSE` lives at `oss/LICENSE`, not repo root, because the root also holds
  private `Artifacts/`. The root README states each subtree's licence.
- `commercial/` is a future sibling of `oss/` that depends on `oss/engine` as a
  library. It is not created now (no speculative empty directory).

## Attack loop

`run.py` orchestrates one run end to end:

1. **Load scenario** from `scenarios.yaml`: id, category, delivery channel, success
   condition, ATLAS/OWASP tags.
2. **Plant canaries.** `canary/` seeds per-run HMAC tokens into the target's data and
   arms the tool mirror for high-risk tools. Tokens are minted fresh per run.
3. **Attacker plans.** `attacker.py` asks the `Provider` for the next step given the
   scenario goal and the target responses so far. Multi-step, adapts to replies.
4. **Deliver.** The `TargetConnector` sends the step through the scenario's channel
   (direct input, or indirect via a planted document or tool output).
5. **Observe and verify.** Capture the target's reply and any tool calls. Success is a
   canary token hit or the mirror recording a high-risk call. Never an LLM judge.
6. **Record.** Append the step to the evidence store.
7. **Loop** to step 3 until success, a cap, or scenario end.
8. **Score and report.** `score.py` then `report/` emit JSON and HTML.

Caps (per-scenario step limit, token limit, rate limit) and the kill switch live in
`run.py`, not in the attacker or provider, so no scenario or provider can bypass them.

## Seams

Two interfaces, each with one implementation in this release. No plugin machinery
until a second implementation exists.

```python
# providers/base.py
class Provider(Protocol):
    def plan(self, goal: str, history: list[Turn]) -> Step: ...
# ollama.py is the default; a frontier model uses the same interface, chosen by env var.

# connectors/base.py
class TargetConnector(Protocol):
    def deliver(self, step: Step) -> Observation: ...   # reply + observed tool calls
    def plant(self, canaries: list[Canary]) -> None: ...
# http.py = generic HTTP agent; mcp.py = MCP client (fixture AND DVMCP).
```

- A scenario owns delivery and verification; a connector owns transport. A scenario
  works over any connector that supports its channel.
- DVMCP needs no special code: it speaks MCP, so `mcp.py` drives it like the fixture.
  Because DVMCP has no canary seeding, verification against it falls back to
  mirror-capture. This is a documented limitation.

## Canary, mirror and evidence model

**Canary tokens** (`canary/tokens.py`):
`token = HMAC(run_key, run_id + scenario_id + slot)`, truncated; `run_key` is random
per run. Planted into target data as a do-not-touch record, a honey credential, or a
document with a hidden marker. A token is worthless if leaked — it maps to nothing
real. A **hit** is that exact token appearing where it should not: in the agent's
output, in an outbound call, or at a beacon endpoint.

**Tool mirror** (`canary/mirror.py`), record-only and fail-closed:

| Call class | Route |
| --- | --- |
| Read-only | Pass through to the real tool (the chain needs real state to branch) |
| Mutating / high-risk | Route to the mirror: record call and args, execute nothing |
| Unclassifiable | Block and flag (fail-closed) |

Record-only is the only tier in this release. Sandbox-execute is deferred to Phase 2.

**Proof primitives:**
- **Mirror capture** — the agent invoked a mutating tool with the right args. Proves
  intent and capability. Can over-report, because a real control might have blocked it.
- **Canary trigger** — a planted artifact was touched. Proves the action reached a
  resource.
- **Combined** — base is mirror capture; a canary trigger upgrades confidence. The
  strongest findings carry both.

**Evidence store** (`evidence/store.py`): one append-only JSONL file per run under
`runs/<run_id>/`. Each record carries `run_id`, `step_no`, `ts` (UTC), `target_host`,
`target_identity`, `channel`, `payload`, `observation`, `tool_calls[]`,
`canary_hits[]`, and `verdict`. `target_host`, `target_identity`, and `ts` are present
from day one because that is exactly what the later Wazuh detection check queries
against, with no engine change needed. The file is append-only and holds full
payloads, so a run is replayable. The report reads this file; nothing else is the
source of truth.

## Fixture

The thin vulnerable target the engine drives for the five-minute demo. Discipline:
**real exploit, fake blast radius.** Every vulnerability is genuinely reachable, but
what leaks is a per-run canary over fabricated data. No scenario grants a real
primitive (disk, exec, env, network) on the host.

**`fixture/agent/` — vulnerable HTTP support agent (thin):**
- Tools: `lookup_order` (read-only, pass-through), `issue_refund` (mutating → mirror),
  `send_email` (mutating → mirror).
- System prompt carries a honey credential (system-prompt-leak surface).
- Folds inbound "email" / uploaded "doc" into context unsanitised (indirect-injection
  surface).
- No authorization at the tool boundary (excessive-agency surface).

**`fixture/mcp/` — vulnerable MCP server (MCP Python SDK):**
- One tool with a poisoned description (hidden instructions in metadata).
- One over-broad-scope tool reaching a canary record.
- Canary-seeded fabricated data.

**Scenario-to-surface coverage:**

| Scenario | Fixture surface | Success |
| --- | --- | --- |
| Direct prompt injection | agent chat | mirror logs restricted tool call on canary |
| Indirect prompt injection | planted email/doc | billing mirror logs refund to canary account |
| Tool misuse / excessive agency | refund/email tools | mirror captures out-of-policy args (canary payee) |
| Data exfiltration | honey token + beacon | token reaches canary beacon endpoint |
| MCP tool poisoning | `fixture/mcp` poisoned tool | agent follows embedded instruction → mirrored canary action |

**Safety, non-negotiable:**
- `docker compose up` binds `127.0.0.1` only; the README says never to expose it.
- Canaries are minted per run; the fixture holds no real data.
- Fixture code is never imported by the engine package; it is a target reached only
  over HTTP/MCP.
- A loud "INTENTIONALLY VULNERABLE" banner, matching the LLMVault / DVMCP norm.

Limits: the fixture covers the five basic categories only — enough to prove the loop
and the demo. The bundled fixture agent's own responses are scripted-deterministic so
the demo reproduces reliably; the *attacker* side is the real LLM. A real-LLM fixture
mode is a later option.

## CLI

Entry point `aphasia` (`cli.py`):

```
aphasia run        # run scenarios against a target
aphasia list       # list scenarios (id, category, ATLAS/OWASP)
aphasia report     # re-render a past run's report from its evidence file
```

`run` flags:

| Flag | Default | Meaning |
| --- | --- | --- |
| `--target` | `fixture` | `fixture` \| HTTP URL \| MCP endpoint (DVMCP goes here) |
| `--scenario` | all basic | scenario id(s) to run |
| `--provider` | `ollama` | LLM backend for the attacker |
| `--ollama-host` | `$OLLAMA_HOST` | remote Ollama base URL |
| `--max-steps` | `6` | per-scenario step cap |
| `--out` | `runs/<run_id>/` | evidence + report directory |

The five-minute path the README sells:

```
docker compose -f fixture/docker-compose.yml up -d      # vulnerable target
export OLLAMA_HOST=https://<remote-ollama>               # your Ollama server
uvx aphasia run                                      # fixture target, basic scenarios
# → runs/<id>/report.html + report.json + evidence.jsonl
```

Output per run:
- `evidence.jsonl` — append-only, the source of truth.
- `report.json` — scenarios, verdicts, canary hits, exposure score.
- `report.html` — human view: per-scenario pass/fail, the proven attack path, the
  evidence trail. This is the artifact people screenshot and share.

Exit code is non-zero if any scenario succeeded (an agent was exploited), so CI can
gate on it later. That is the whole "CI mode" for this release — no extra subsystem.

Limits: no config file (flags and env only; a config file arrives with scheduling in
Phase 2) and no `discover` command (discovery is a later enterprise phase; you point
`--target` yourself).

## Testing strategy

The attacker is a real LLM (remote Ollama, non-deterministic); the fixture is
scripted-deterministic. Determinism in tests comes from stubbing the provider, never
from the real model.

| Layer | What | Uses LLM | In CI |
| --- | --- | --- | --- |
| Unit | canary HMAC determinism; mirror routing; evidence append; scenario verify; score | no | yes |
| Sandbox-inert (safety) | mirror executes nothing; fixture grants no real disk/exec/env/net primitive | no | yes |
| Integration | full loop with `StubProvider` (scripted steps) vs fixture → deterministic canary hit | no (stub) | yes |
| Live (opt-in, marked) | real remote Ollama attacker vs fixture | yes | no |

- **`StubProvider`** returns scripted steps through the same `Provider` interface, so
  the whole loop is testable offline and deterministic, with no network or secret.
  This keeps CI green without the remote Ollama.
- **Sandbox-inert tests are the non-negotiable ones.** Same discipline as LLMVault's
  `test_render_engine_is_sandboxed`: assert the mirror runs nothing and the fixture
  leaks only canaries. A regression that turned the mirror into a real executor fails
  CI. This is the security-critical path.
- **Mirror routing test** covers all three classes: read passes through, mutating
  routes to the mirror, unclassifiable blocks (fail-closed).
- **Live test** is marked `@pytest.mark.live`, skipped by default, needs `OLLAMA_HOST`.
  Run manually before a release to confirm a real model drives a chain to a canary hit.

The one self-check that must exist: an `assert`-based integration test —
`StubProvider` + fixture → a canary hit recorded in `evidence.jsonl`. If the loop,
mirror, or canary wiring breaks, it fails.

CI (`.github/workflows/`) runs lint, unit, sandbox-inert, and integration, all
offline. The live layer is excluded. No coverage gates or build matrix in this
release; one Python version.

## Dependencies

- `mcp` (official MCP Python SDK) — MCP client and the fixture MCP server.
- An HTTP client (stdlib `urllib` or `httpx`) — Ollama provider and HTTP connector.
- A web micro-framework (Flask or stdlib `http.server`) — fixture agent.
- `pytest` — tests.

Kept deliberately small to protect the "clone and run" promise. The Ollama provider
and the HTTP connector should prefer the stdlib where it is enough.

## Environment notes

- Docker is installed; user `mamber` is in the `docker` group, but the group is not
  yet refreshed in the current shell. The first `docker compose up` must run via
  `sudo docker` or after `newgrp docker` / a fresh login.
- Ollama is a remote server; its URL is supplied at wiring time. The provider must
  take a configurable base URL, never assume `localhost:11434`.

## Open questions for later phases (not blocking this release)

- Whether the Wazuh detection check ships open source or commercial.
- Final project / package name (`aphasia` is a working placeholder).
- Which basic scenarios map to which exact ATLAS technique IDs — verified against
  ATLAS 2026.09 in the attack-library spreadsheet, to be mirrored into `scenarios.yaml`.
```

