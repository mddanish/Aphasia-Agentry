#!/usr/bin/env bash
# Demo for a README GIF. Record it with asciinema + agg:
#   asciinema rec demo.cast -c "bash docs/demo.sh"
#   agg demo.cast docs/assets/demo.gif
# Run from the repo root with the fixture reachable (docker compose up first).
set -euo pipefail

say() { printf '\n\033[1;36m$ %s\033[0m\n' "$*"; sleep 1; }

say "docker compose -f fixture/docker-compose.yml up -d"
docker compose -f fixture/docker-compose.yml up -d >/dev/null
sleep 2

cd engine

say "aphasia list"
uv run aphasia list
sleep 2

say "aphasia run --mode seed        # no LLM, no API key"
uv run aphasia run --mode seed
sleep 1

say "open runs/<id>/report.html      # all 10 OWASP LLM categories, canary-proven"
sleep 2
