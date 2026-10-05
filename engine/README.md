# Aphasia Agentry

**Agentic BAS — breach & attack simulation for AI agents and MCP servers.**
Drive an attacker (curated seed payloads and/or any LLM) against a target, prove impact
with per-run canaries, and get a report mapped to the **OWASP LLM Top 10** and MITRE ATLAS.

[![PyPI](https://img.shields.io/pypi/v/aphasia-agentry)](https://pypi.org/project/aphasia-agentry/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/mddanish/Aphasia-Agentry/blob/main/LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://github.com/mddanish/Aphasia-Agentry)
[![OWASP LLM Top 10](https://img.shields.io/badge/OWASP-LLM%20Top%2010-8A2BE2)](https://github.com/mddanish/Aphasia-Agentry/blob/main/docs/scenarios.md)

![Aphasia Agentry report](https://raw.githubusercontent.com/mddanish/Aphasia-Agentry/main/docs/assets/report-hero.png)

## Install

    pip install aphasia-agentry        # or: uvx aphasia-agentry, pipx install aphasia-agentry

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

No LLM, no API key — reproducible coverage from the seed-payload library (needs the bundled
Docker fixture, from a repo checkout):

    docker compose -f fixture/docker-compose.yml up -d
    aphasia run --mode seed        # then open runs/<id>/report.html

Point it at your own agent instead of the fixture:

    aphasia run --target http://host/chat --model gpt-4o-mini     # any litellm model

`aphasia list` shows the scenarios; `aphasia payloads` the seed library; `aphasia --help` the rest.

## Links

Full documentation, the vulnerable fixture, contributing guide and source:
**https://github.com/mddanish/Aphasia-Agentry**

> The bundled fixture is **intentionally vulnerable** — run it on localhost only, never expose it.

Licensed under Apache-2.0.
