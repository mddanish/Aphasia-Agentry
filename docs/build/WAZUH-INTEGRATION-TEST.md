# Wazuh integration test — VM runbook

Run this on your own VM after cloning the repo. It validates the SOC-detection half of Aphasia
end to end, using the assets already in this repo (`deploy/wazuh/`). No separate kit, no bundled
copy of Aphasia — everything is here in the clone.

```bash
git clone https://github.com/mddanish/Aphasia-Agentry
cd Aphasia-Agentry
bash scripts/vm-setup.sh          # prereq check + fixture up (see below)
```

Needs: Docker + Compose v2, 8 GB RAM free, `vm.max_map_count=262144`, Python 3.11+, uv.
Full Wazuh setup steps and credentials are in [WAZUH.md](WAZUH.md); this file is the test itself.

## Status — what runs today vs what you build first

| Piece | State | Needed for |
|---|---|---|
| Wazuh rules `deploy/wazuh/aphasia_rules.xml` (1002xx direct, 1003xx proxy) | ready | Stages A–B |
| CDB lists + `wazuh-logtest` samples | ready | Stage B |
| Attack engine, canaries, evidence log (`aphasia run`) | ready | Stage C |
| Proxy recorder `aphasia/proxy/recorder.py` | ready | Stage E |
| Fixture telemetry logging (`$APHASIA_LOG`) + `X-Aphasia-*` headers | ready (Phase 1) | Stage C→D |
| `aphasia detect` (Wazuh correlation) | ready (Phase 3) | Stage D |
| `aphasia proxy` command + `fixture/llm-agent` | ready (Phase 4+5) | Stage E |

Stages A–E are all built. Stage E needs a tool-calling model behind the proxy (Ollama
`qwen2.5:7b-instruct`, or a hosted model) and the lab agent container; see below.

## Stage A — bring Wazuh up

```bash
sudo sysctl -w vm.max_map_count=262144
git clone -b v4.14.11 --depth 1 https://github.com/wazuh/wazuh-docker ~/wazuh-docker
cd ~/wazuh-docker/single-node
docker compose -f generate-indexer-certs.yml run --rm generator
export APHASIA_REPO=$(cd ~/Aphasia-Agentry && pwd)
cp "$APHASIA_REPO/deploy/wazuh/docker-compose.override.yml" .
mkdir -p "$APHASIA_REPO/fixture/logs" "$APHASIA_REPO/engine/runs/proxy"
# add the <localfile> + <list> lines from deploy/wazuh/manager-ossec-snippet.xml
#   into config/wazuh_cluster/wazuh_manager.conf  (see WAZUH.md step 4)
docker compose up -d
```

Pass when: `docker compose ps` shows manager, indexer, dashboard healthy; dashboard reachable on
`https://<vm>`.

## Stage B — prove the rules fire (no attack yet)

```bash
docker compose exec wazuh.manager /var/ossec/bin/wazuh-logtest
# paste each line of deploy/wazuh/samples/telemetry.jsonl, one at a time
```

Pass when each line matches the rule in [deploy/wazuh/samples/expected.md](../../deploy/wazuh/samples/expected.md):
100201/100205 (telemetry), 100210 refund-to-unseen-payee, 100240 unknown recipient, 100230 MCP
description change, 100260 correlation, 100250 cost, and the proxy rules 100320/100340/100310.
If a sibling rule wins in the wrong order, reorder in `aphasia_rules.xml` (first match wins) and
`docker compose restart wazuh.manager`.

## Stage C — run a real attack, get evidence

```bash
cd "$APHASIA_REPO"
docker compose -f fixture/docker-compose.yml up -d
cd engine && uv sync && uv run aphasia run --mode seed
# -> runs/<id>/evidence.jsonl  +  report.html/json/md
```

Pass when the report shows canary-proven findings (indirect_injection, data_exfil,
mcp_tool_poisoning, tool_misuse, …). This is the attacker + proof half — already green.

The fixture now writes telemetry to `$APHASIA_LOG` when set (Phase 1). Point it at the mounted log:

```bash
export APHASIA_LOG="$APHASIA_REPO/fixture/logs/fixture.jsonl"   # set in fixture/docker-compose.override.yml
```

To prove the Wazuh pipe without a full run, inject one line by hand:

```bash
echo '{"ts":"2026-12-04T10:15:04Z","source":"aphasia-fixture","component":"agent","event":"tool_call","tool":"issue_refund","mutating":true,"args":{"order_id":"x","payee":"unknown-1"},"honey":true,"session":"t"}' \
  >> "$APHASIA_REPO/fixture/logs/fixture.jsonl"
sleep 8
curl -sk -u admin:SecretPassword "https://localhost:9200/wazuh-alerts-4.x-*/_search?q=rule.id:100210&size=1" | head -c 400
```

Pass when the indexer returns a rule 100210 alert for that line.

## Stage D — automated detection-gap (ready)

```bash
export APHASIA_WAZUH_URL=https://<vm>:9200
read -rs APHASIA_WAZUH_PASSWORD && export APHASIA_WAZUH_PASSWORD
cd "$APHASIA_REPO/engine"
uv run aphasia run --mode seed            # fixture logs telemetry; engine tags X-Aphasia-* headers
sleep 20
uv run aphasia detect --run runs/<id> --insecure
uv run aphasia tui --run runs/<id>        # sections 3 Steps, 6 Gaps now populated
```

Pass when a run yields **≥3 detected, ≥3 silent, ≥1 no-telemetry**, and `detect --from-file
deploy/wazuh/samples/indexer_search_response.json` works offline for a repeatable check.

## Stage E — proxy mode (ready)

```bash
cd "$APHASIA_REPO/engine"
uv run aphasia setup                      # enable proxy, set upstream model/key
uv run aphasia setup                      # enable proxy, set upstream model + key
uv run aphasia proxy start --provider-model ollama_chat/qwen2.5:7b-instruct
# bring up the lab agent pointed at the proxy (copy the override, set the printed key):
cp ../fixture/llm-agent/docker-compose.override.yml ../fixture/docker-compose.override.yml
OPENAI_API_KEY=<proxy key> docker compose -f ../fixture/docker-compose.yml up -d llm-agent
uv run aphasia run --mode seed --target http://127.0.0.1:8002/chat --proxy runs/proxy
uv run aphasia detect --run runs/<id> --insecure --proxy runs/proxy
uv run aphasia proxy stop
```

Pass when the prompt-leak and tool-output-injection steps move from **silent** (direct) to
**detected** (proxy rules 1003xx), and TUI section 7 Trace shows the gateway context in / tool
calls out.

## Record it

`asciinema rec` the terminal flow and an OBS capture of the Wazuh dashboard showing the same
alerts — both modes. Keep copies for the talk's backup video.
