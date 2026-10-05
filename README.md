# Aphasia Agentry

**Agentic BAS — breach & attack simulation for AI agents and MCP servers.**
Drive an attacker (curated seed payloads and/or any LLM) against a target, prove impact
with per-run canaries, and get a report mapped to the **OWASP LLM Top 10** and MITRE ATLAS.

[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](engine/pyproject.toml)
[![OWASP LLM Top 10](https://img.shields.io/badge/OWASP-LLM%20Top%2010-8A2BE2)](docs/scenarios.md)
[![Proof](https://img.shields.io/badge/verdicts-canary--proven-brightgreen)](#how-it-works)
[![CI](https://github.com/mddanish/Aphasia-Agentry/actions/workflows/ci.yml/badge.svg)](https://github.com/mddanish/Aphasia-Agentry/actions/workflows/ci.yml)

![Aphasia Agentry report](docs/assets/report-hero.png)

> **INTENTIONALLY VULNERABLE.** The fixture in [`fixture/`](fixture/) is for authorized,
> self-hosted testing only. Run it on localhost; never expose it to a network.

## Install

    uvx aphasia-agentry --help          # run without installing
    pipx install aphasia-agentry        # or: pip install aphasia-agentry

From source:

    git clone https://github.com/mddanish/Aphasia-Agentry
    cd Aphasia-Agentry/engine && uv run aphasia --help

## Why

Most agent red-teaming grades a model's *output* with an LLM judge. Aphasia Agentry asks a
harder question — **did the attack actually reach impact?** — and answers it with evidence:

- **Proof, not judgement.** A finding is a touched canary record, a used honey token, or a
  mutating tool call captured by a record-only mirror. Never a model's self-assessment.
- **Any LLM, or none.** Seed mode runs curated payloads with **no LLM at all** (reproducible,
  runs in seconds). Add an adaptive attacker via [litellm](https://github.com/BerriAI/litellm):
  OpenAI, Anthropic, Gemini, Groq, OpenRouter, Bedrock, local vLLM/LM Studio, Ollama.
- **Full OWASP LLM Top 10.** 11 scenarios across LLM01–LLM10, mapped to MITRE ATLAS.
- **Safe by construction.** The bundled vulnerable fixture is sandbox-inert — real exploit,
  fake blast radius: no disk, exec, env or network from any attack.

## Quickstart

No LLM, no API key — reproducible coverage from the seed-payload library:

    docker compose -f fixture/docker-compose.yml up -d
    cd engine && uv run aphasia run --mode seed      # then open runs/<id>/report.html

Add an adaptive LLM attacker (the `--model` string selects the provider):

    aphasia run --model gpt-4o-mini                        # OpenAI (OPENAI_API_KEY)
    aphasia run --model anthropic/claude-3-5-haiku         # Anthropic (ANTHROPIC_API_KEY)
    aphasia run --model ollama/llama3.2:1b --api-base http://<host>:11434   # local Ollama

`--mode hybrid` (default) runs the seeds first, then the LLM adapts. See `aphasia --help`,
[docs/quickstart.md](docs/quickstart.md) and [docs/scenarios.md](docs/scenarios.md).

### Demo

![Aphasia Agentry seed-mode demo](docs/assets/demo.gif)

Generated from [docs/demo.sh](docs/demo.sh) — record your own with
`asciinema rec demo.cast -c "bash docs/demo.sh" && agg demo.cast docs/assets/demo.gif`.

## How it works

    scenario + payload → attacker → delivery (HTTP / MCP) → target agent → tool calls
                                                                   │
            per-run HMAC canaries planted ───────────────► canary hit?  ──► SUCCESS (proven)
            record-only fail-closed mirror ──────────────► mutating call captured? ──► mirror_only
            cost markers ([[COST:n]]) ───────────────────► budget breached? ──► metered (LLM10)

Every step is appended to an append-only `evidence.jsonl` (12 keys incl. `scenario_id`).
The report (`report.html` / `report.json`) shows, per scenario: the attack, its ATLAS/OWASP
mapping, the canary-backed proof (winning payload, target reply, captured tool call), a
step-by-step timeline, and a concrete fix.

## Coverage (OWASP LLM Top 10)

| OWASP | Scenario | ATLAS |
| --- | --- | --- |
| LLM01 | direct_injection, indirect_injection | AML.T0051.000 / .001 |
| LLM02 | data_exfil | AML.T0086 |
| LLM03 | mcp_tool_poisoning | AML.T0110 |
| LLM04 | memory_poisoning | AML.T0099 |
| LLM05 | output_handling | — |
| LLM06 | tool_misuse | AML.T0053 |
| LLM07 | system_prompt_leak | AML.T0056 |
| LLM08 | rag_exfil | AML.T0086 |
| LLM09 | misinformation | AML.T0031 |
| LLM10 | denial_of_wallet | AML.T0034.002 |

`aphasia list` prints this with seed-payload counts; `aphasia payloads` shows the library.

## Attacker modes

- `seed` — curated [payloads.yaml](engine/src/aphasia/data/payloads.yaml) only, no LLM. Reproducible; proves all 11 vs the fixture.
- `adaptive` — an LLM plans every step (any litellm model).
- `hybrid` (default) — seeds first, then the LLM adapts on what's unsolved.

## Targets

- `--target fixture` — the bundled vulnerable agent (HTTP on `127.0.0.1:8000`).
- `--target http://host/chat` — your own HTTP agent (`{message, channel}` → `{reply, tool_calls}`).
- `--target <mcp-endpoint>` — any MCP server (also drives a Damn-Vulnerable-MCP server).

## Project layout

- [`engine/`](engine/) — the `aphasia` Python package (CLI, attacker, connectors, canary/mirror, report)
  - [`scenarios.yaml`](engine/src/aphasia/data/scenarios.yaml) — the 11 OWASP LLM Top 10 scenarios
  - [`payloads.yaml`](engine/src/aphasia/data/payloads.yaml) — the curated seed-payload library
- [`fixture/`](fixture/) — the deliberately-vulnerable HTTP agent + MCP server (Docker, localhost only)
- [`docs/`](docs/) — [quickstart](docs/quickstart.md), [scenarios](docs/scenarios.md), [demo script](docs/demo.sh), assets

## Contributing

New seed payloads and scenarios are the easiest way to help — see [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

This project ships intentionally vulnerable code for testing. To report a vulnerability in
Aphasia Agentry *itself*, see [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE) (see also [NOTICE](NOTICE)). "Aphasia Agentry" names this project; the code is Apache-2.0.
