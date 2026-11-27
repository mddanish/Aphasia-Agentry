# Build plan and Claude Code prompts

Run each phase in a fresh Claude Code session from the repo root. Paste the prompt as is.
Commit at the end of every phase (`git commit` on branch `feat/tui-wazuh`).

Priority: **direct mode must ship.** Proxy mode is act 2 of the demo; if the lab LLM agent is not
stable by Tue 1 Dec, show proxy mode from a recorded run (`aphasia tui --run <recorded run>`).

| Day | Phase | Done when |
|---|---|---|
| Sat 28 Nov | 0 Bootstrap, 1 Telemetry | fixture writes `fixture/logs/fixture.jsonl` during `aphasia run` |
| Sat 28 Nov | 2 Wazuh up | rules load, `wazuh-logtest` matches `deploy/wazuh/samples/expected.md` (lines 1–10) |
| Sun 29 Nov | 3 Detect | `aphasia detect` works offline (sample file) and live |
| Sun 29 Nov | 4 Proxy command | `aphasia proxy start/status/stop` runs the recorder via uvx; agent settings printed |
| Mon 30 Nov | 5 Lab LLM agent | `fixture/llm-agent` through the proxy; ≥4 scenarios proven at temperature 0 |
| Mon 30 Nov | 5b Catalog scenarios | top uncovered techniques get scenarios (see Phase 5b) |
| Mon 30 Nov | 6 TUI live | `aphasia tui` on real runs of both modes; `r`, `w` keys; `7 Trace` filled |
| Tue 1 Dec | 7 Demo hardening | 5 clean runs per mode, rule tuning, 100×30 check |
| Wed 2 Dec | 8 Backup + slides | recordings of both modes, screenshots into the deck |
| Thu 3 Dec | Buffer | dry run with a timer |

---

## Phase 0: bootstrap (shell, no Claude)

```
bash aphasia-buildkit/scripts/bootstrap_vm.sh /path/to/Aphasia-Agentry
```

## Phase 1: fixture telemetry

```
Read CLAUDE.md and docs/build/SPEC.md sections 3 and 4.
Implement the telemetry contract in fixture/agent/app.py and fixture/mcp/server.py:
- log helper writing JSON lines to $APHASIA_LOG (no-op when unset)
- events inbound_message, tool_call, agent_reply, mcp_tools_list with the exact fields in SPEC §3
- honey flag from the seeded STATE; desc_hash/desc_changed in the MCP server
- APHASIA_RUGPULL=1 swaps the fetch_weather description after the first tools/list
- engine connectors send X-Aphasia-Run / X-Aphasia-Scenario / X-Aphasia-Step headers
Add fixture tests for every event shape. Keep all existing tests green.
Then: copy deploy/lab/fixture-compose.override.yml to fixture/docker-compose.override.yml,
bring the fixture up, run `aphasia run --mode seed`, and show me 5 lines of fixture/logs/fixture.jsonl.
```

## Phase 2: Wazuh (mostly shell, see docs/build/WAZUH.md)

```
Read docs/build/WAZUH.md. Walk me through bringing up Wazuh 4.14.11 single-node with the
override in deploy/wazuh/. Then run every line of deploy/wazuh/samples/telemetry.jsonl through
wazuh-logtest inside the manager container and compare with samples/expected.md.
If a sibling rule wins in the wrong order, fix aphasia_rules.xml and re-test. Do not add rules
for the deliberate gaps listed at the top of the rules file.
```

## Phase 3: `aphasia detect`

```
Read docs/build/SPEC.md section 5. Implement engine/src/aphasia/detect/wazuh.py and the
`aphasia detect` subcommand with httpx only. Settings from aphasia.config ([wazuh] +
APHASIA_WAZUH_PASSWORD, see SPEC §12); --insecure overrides for one run.
Support --from-file for offline use. Write detections.json and run_view.json; run_view.json must
have exactly the keys of engine/src/aphasia/tui/demo_run.json (deploy_mode and exchanges included).
Gap fixes come from data/gap_fixes.yaml. Unit-test matching and classification with
deploy/wazuh/samples/indexer_search_response.json (strong match, fallback match, silent, missing).
```

## Phase 4: proxy command

```
Read docs/build/SPEC.md sections 1a, 9 and 12, engine/src/aphasia/proxy/recorder.py and
engine/src/aphasia/config.py (both done, tested). The proxy uses ONLY [upstream] and
APHASIA_UPSTREAM_API_KEY; the attacker LLM is never involved.
Implement `aphasia proxy start|status|stop` and `aphasia run --proxy DIR` exactly as SPEC §9 says.
The proxy MUST run via `uvx --from "litellm[proxy]==1.111.0" litellm` in its own env: do not add
litellm[proxy] to pyproject (rich version conflict with textual). Copy recorder.py next to the
generated config with importlib.resources. Spawn with a clean env built from scratch (SPEC §9 step 3).
Add a test that the spawned env never contains APHASIA_ATTACKER_API_KEY or OPENAI_API_KEY. Test: unit-test config generation and the run-context file; then an integration
test (marked `live`) that starts the proxy against a tiny fake OpenAI server returning a tool call,
sends one request, and asserts llm_exchange + llm_tool_call lines in proxy.jsonl.
```

## Phase 5: lab LLM agent

```
Read docs/build/SPEC.md section 10. Build fixture/llm-agent/ (Flask + openai SDK + mcp client),
same /chat and /seed contract and safety rules as fixture/agent/app.py, Dockerfile, compose service
on 127.0.0.1:8002 with OPENAI_BASE_URL pointing at the proxy on the host. Start the proxy with
ollama_chat/qwen2.5:7b-instruct, run `aphasia run --mode seed --target http://127.0.0.1:8002/chat
--proxy runs/proxy`, and tune seed payloads in data/payloads.yaml (add, don't remove) until
indirect_injection, data_exfil, mcp_tool_poisoning and system_prompt_leak are proven at
temperature 0 in 3 runs out of 3. Show me runs/proxy/proxy.jsonl for one scenario.
```

## Phase 5b: fill high-value catalog gaps (optional, after the core demo works)

```
Read docs/build/SPEC.md section 13 and run `aphasia catalog`. For the demo, add scenarios for the
highest-impact uncovered techniques (scenario == "" in the catalog), in this order, each with seed
payloads and a canary/mirror success condition, then set the technique's `scenario` field:
  AP-T27 tool rug pull, AP-T28 tool-name shadowing, AP-T17 prompt-secret extraction,
  AP-T43 goal hijacking, AP-T22 markdown-link exfil.
Keep fixture safety rules. Prefer techniques that are proxy_better so the proxy act of the talk is
richer. Do not add scenarios for testable:none techniques. Re-run `aphasia catalog` to confirm the
runnable count rose and all tests pass.
```

## Phase 6: TUI live

```
Read docs/build/TUI_STYLE.md and SPEC section 6. The starter in engine/src/aphasia/tui/ is the
visual baseline: keep its look. Add `aphasia tui [--run DIR] [--demo]`, then the key actions
r (run in a worker, live ACTIVITY), w (detect in a worker, refresh), f (silent filter),
section 8 Catalog already lists categories; wire enter to prefill a --category run.
e (export gaps.md), enter (drill-down). Setup wizard (s, first run) exists: keep it, wire r/w to
config.load(). Status bar shows direct/proxy and a green/red dot from a cheap
indexer health call. 7 Trace reads run_view.exchanges. Test every key with App.run_test at 120x40
and 100x30. Render SVG screenshots of all 7 sections into docs/assets/tui/ and show them to me.
```

## Phase 7: demo hardening

```
Run the full flow 5 times per mode. Direct: fixture reset, aphasia run --mode seed, wait 20 s,
aphasia detect, aphasia tui. Proxy: same with the lab LLM agent and --proxy runs/proxy.
Report any step whose result changes between runs and fix the cause (timing window, rule order,
missing header, model nondeterminism). Direct target per run: >=3 detected, >=3 silent, >=1 missing.
Proxy target: the prompt-leak and tool-output-injection steps move from silent to detected.
Add scripts/demo.sh direct|proxy that runs the whole flow with one command.
```

## Phase 8: backup

Record with `asciinema rec` then `agg` (already used in docs/demo.sh), plus an OBS screen
recording of the Wazuh dashboard showing the same alerts. Both modes. Keep copies on a USB stick.
