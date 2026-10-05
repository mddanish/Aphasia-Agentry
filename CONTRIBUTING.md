# Contributing to Aphasia Agentry

Thanks for helping! New **seed payloads** and **scenarios** are the easiest and most valuable
contributions — they directly widen attack coverage.

## Setup

- Python 3.11+, `uv`. The package lives in `engine/`.
- Engine tests (offline, no network): `cd engine && uv run pytest -m "not live"`
- Fixture tests (sandbox-inert + end-to-end seed run):
  `uv run --with-editable ./engine --with flask --with "mcp>=2" --with pytest python -m pytest fixture/tests`

## Add a seed payload

Edit `payloads.yaml`: add realistic known-bad strings under the matching scenario id. Order
matters for multi-phase scenarios (e.g. `memory_poisoning` plants on the first turn, recalls
on a later one). Only add payloads you have the right to redistribute under Apache-2.0 — the
library is a project-owned starter set, not a copy of an externally-licensed corpus.

Verify locally against the bundled fixture:

    docker compose -f fixture/docker-compose.yml up -d
    cd engine && uv run aphasia run --mode seed

## Add a scenario

1. Add an entry to `scenarios.yaml` (id, category, channel, goal, success_condition, atlas, owasp).
2. Give the fixture a deliberately-vulnerable, **sandbox-inert** surface for it in
   `fixture/agent/app.py` (string/dict ops only — no disk/exec/env/network) and a test in
   `fixture/tests/test_agent_sandbox.py`.
3. Add seed payloads in `payloads.yaml`.
4. If it maps to a MITRE ATLAS technique, add the id + display name in `engine/src/aphasia/report/render.py`.

## Rules

- Every change ships with a test. Keep PRs small and focused.
- Never weaken a safety invariant (record-only mirror, sandbox-inertness, per-run canaries).
- By contributing you agree your work is licensed under Apache-2.0.
