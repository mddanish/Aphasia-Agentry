#!/usr/bin/env bash
# Aphasia Agentry — VM prerequisite check + fixture bring-up for the Wazuh integration test.
# Run from a fresh clone: `bash scripts/vm-setup.sh`. Does NOT start Wazuh (see docs/build/WAZUH.md).
# Idempotent; starts nothing destructive.
set -euo pipefail
cd "$(dirname "$0")/.."
REPO="$(pwd)"
ok(){ printf '  \033[32m✓\033[0m %s\n' "$*"; }
warn(){ printf '  \033[33m!\033[0m %s\n' "$*"; }
die(){ printf '  \033[31m✗\033[0m %s\n' "$*"; exit 1; }

echo "== prerequisites"
command -v git >/dev/null && ok "git $(git --version | awk '{print $3}')" || die "git missing"
P=$(command -v python3 || true); [ -n "$P" ] || die "python3 missing"
"$P" -c 'import sys; sys.exit(0 if sys.version_info>=(3,11) else 1)' || die "python 3.11+ needed"
ok "python $("$P" -V | awk '{print $2}')"
if ! command -v uv >/dev/null; then
  warn "uv missing — installing to ~/.local/bin"; curl -LsSf https://astral.sh/uv/install.sh | sh
  export PATH="$HOME/.local/bin:$PATH"
fi
ok "uv $(uv --version | awk '{print $2}')"
if command -v docker >/dev/null && docker compose version >/dev/null 2>&1; then
  ok "docker $(docker --version | awk '{print $3}' | tr -d ,) + compose"
else warn "docker + compose v2 needed (fixture + Wazuh): https://docs.docker.com/engine/install/"; fi
MEM=$(awk '/MemTotal/{printf "%d",$2/1024/1024}' /proc/meminfo)
[ "$MEM" -ge 8 ] && ok "RAM ${MEM} GB" || warn "RAM ${MEM} GB — Wazuh single-node wants 8 GB+"
MMC=$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)
[ "$MMC" -ge 262144 ] && ok "vm.max_map_count $MMC" || warn "run: sudo sysctl -w vm.max_map_count=262144"
command -v ollama >/dev/null && ok "ollama found (proxy-mode model)" || warn "ollama not found — needed only for proxy mode (https://ollama.com)"

echo "== python env + tests"
( cd engine && uv sync && uv run python -m pytest -q --ignore=tests/test_live.py | tail -2 )

echo "== log dirs for Wazuh mounts"
mkdir -p fixture/logs engine/runs/proxy
touch fixture/logs/fixture.jsonl engine/runs/proxy/proxy.jsonl
ok "fixture/logs and engine/runs/proxy ready"

echo "== fixture (intentionally vulnerable — localhost only)"
if command -v docker >/dev/null && docker compose version >/dev/null 2>&1; then
  docker compose -f fixture/docker-compose.yml up -d && ok "fixture up on 127.0.0.1:8000 / :8001"
else warn "docker unavailable — start the fixture yourself when ready"; fi

cat <<NEXT

Next:
  1. Bring up Wazuh 4.14.11:        docs/build/WAZUH.md
  2. Run the integration test:      docs/build/WAZUH-INTEGRATION-TEST.md
  3. Build the missing pieces with Claude Code (Phase 1/3/4/5 prompts): docs/build/PLAN.md
Repo is self-contained — no external kit needed.
NEXT
