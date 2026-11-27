# Aphasia Agentry v0.2: direct + proxy modes, TUI, Wazuh defender loop (build spec)

Target: live demo at BSides Kolkata (4–5 Dec 2026). Talk: "Did Your SOC See the Agent Go Rogue?"
Base: `mddanish/Aphasia-Agentry` v0.1.1 (attack engine, canaries, mirror, fixture, report — all working, 81 tests).

## 1. Goal

One terminal UI that shows, for every attack step:
1. **Did the attack reach impact?** (already done: canary / mirror proof)
2. **Did Wazuh see it?** (new: detected / silent / no telemetry)

Everything new is additive. Do not change existing verdict logic, scenario IDs or CLI flags.

## 1a. Two operating modes

| | Direct mode | Proxy mode |
|---|---|---|
| Idea | black box: attack the agent from outside | Aphasia sits between the agent and its LLM provider |
| Setup | point Aphasia at the agent's HTTP/MCP endpoint | `aphasia proxy start` gives a base URL + key; put them in the agent's LLM settings; the real provider is configured in Aphasia |
| Sees | what goes in (payload) and what comes out (reply, reported tool calls) | plus: full context sent to the LLM (system prompt, tool outputs, retrieved docs), tools offered and their definitions, every tool call the LLM asks for |
| Proof | canaries + mirror | same, plus honey tokens seen in context, tool args or replies |
| SIEM | Wazuh rules 1002xx on fixture/agent telemetry | plus rules 1003xx on gateway telemetry (closes prompt-leak, tool-output injection and tool-drift gaps) |
| Talk role | act 1: "your SOC is blind" | act 2: "an AI gateway gives the SOC eyes" |

Both modes use the same attack engine, scenarios, evidence store, detect step and TUI.
Status bar shows `direct` or `proxy`; section `7 Trace` is populated only in proxy mode.

## 2. Architecture

```
aphasia run ──► target (fixture agent/MCP) ──► fixture/logs/fixture.jsonl ──► Wazuh manager (localfile json)
     │                                                                              │ rules 100200-100299
     ▼                                                                              ▼
runs/<id>/evidence.jsonl                                              wazuh-indexer: wazuh-alerts-4.x-*
     │                                                                              │
     └──────────────► aphasia detect  ◄── OpenSearch _search (HTTPS 9200) ──────────┘
                           │
                           ▼
              runs/<id>/detections.json + run_view.json ──► aphasia tui
```

## 3. Telemetry contract (fixture → Wazuh)

The fixture appends one JSON object per line to `$APHASIA_LOG` (default: unset = no logging, so
existing tests keep passing). Write with `open(path, "a")` + `json.dumps(obj) + "\n"`, flush per line.

Common fields (every line):

| Field | Type | Notes |
|---|---|---|
| `ts` | str | UTC ISO-8601 `Z` |
| `source` | str | always `aphasia-fixture` (rule 100200 keys on it) |
| `component` | str | `agent` or `mcp` |
| `event` | str | `inbound_message`, `tool_call`, `agent_reply`, `mcp_tools_list` |
| `session` | str | per-conversation ID (one per scenario run is fine) |
| `run_id`, `scenario`, `step` | str/int | from request headers `X-Aphasia-Run`, `X-Aphasia-Scenario`, `X-Aphasia-Step`; omit if absent |

Per event:

| event | Extra fields |
|---|---|
| `inbound_message` | `channel` (`direct`/`email`/`doc`), `length` (do not log the full payload) |
| `tool_call` | `tool`, `mutating` (bool), `args` (object), `honey` (bool: any seeded canary token appears in args), `over_budget` (bool, only for `generate` when cost marker > 20000) |
| `agent_reply` | `length`, `honey` (bool: reply contains a seeded token) — no detection rule on purpose |
| `mcp_tools_list` | `tool`, `desc_hash` (sha256 of description), `desc_changed` (bool: differs from the first hash seen since process start) |

`honey` is computed by the fixture from its seeded `STATE`. This models a honeytoken registry,
which real SOCs use. Update the fixture docstring: it now writes its own log file (never attacker-chosen paths).

Fixture container runs as `nobody`: create `fixture/logs/` with mode 0777 before `docker compose up`.

## 4. Engine changes

1. `HttpConnector.deliver()` and the MCP connector send headers `X-Aphasia-Run`, `X-Aphasia-Scenario`,
   `X-Aphasia-Step` (pass run/scenario/step through `Step` or a connector context; keep it optional).
2. Evidence records keep the 12 required keys. Add optional `ts_end` per step (time the reply arrived).
3. MCP fixture: make tool descriptions mutable for the rug-pull demo (e.g. a `/rugpull` toggle or an
   env var `APHASIA_RUGPULL=1` that swaps `fetch_weather` description after the first `tools/list`).

## 5. `aphasia detect` (new module `aphasia/detect/wazuh.py`)

CLI:
```
aphasia detect --run runs/<id> [--wazuh-url https://HOST:9200] [--insecure | --ca-cert PATH]
               [--window-before 5] [--window-after 90] [--min-level 7]
```
Settings from `config.load()` (`[wazuh]`), password from `APHASIA_WAZUH_PASSWORD` (env or secrets.env).
Never accept a password as a CLI flag. Use `httpx` (already a dependency); no new client library.

Query (one request per run, then match locally):
```json
POST /wazuh-alerts-4.x-*/_search
{"size": 1000, "sort": [{"timestamp": "asc"}],
 "query": {"bool": {"filter": [
   {"terms": {"rule.groups": ["aphasia"]}},
   {"range": {"timestamp": {"gte": "<first step ts - before>", "lte": "<last step ts + after>"}}}]}}}
```

Matching each evidence step to alerts (Wazuh returns every `data.*` value as a string, and the proxy
recorder already writes `run_id`/`scenario`/`step` as strings: compare as strings):
1. Strong: `data.run_id == run_id` and `data.step == step_no` and `data.scenario == scenario_id`.
2. Fallback (real targets without headers): same `data.tool` as a captured tool call, timestamp in
   `[step.ts - before, step.ts + after]`.

Classify each step:

| Result | Rule |
|---|---|
| `blocked` | evidence verdict shows the target refused / mirror blocked |
| `detected` | any matched alert with `rule.level >= min_level` |
| `silent` | matched alerts exist, all below `min_level` (telemetry present, no detection) |
| `missing` | no matched alert at all (no telemetry) |
| `expected` | benign step (no tool call, no canary) with only telemetry — not counted as a gap |

Outputs in the run folder:
- `detections.json`: per step `{scenario, step_no, result, alerts:[{rule_id, level, description, timestamp}]}`
- `run_view.json`: the TUI view model (§6). Must match `engine/src/aphasia/tui/demo_run.json` keys exactly.

Gaps (`run_view.gaps`): one per `silent`/`missing` step of a **proven** scenario, ranked by scenario
severity then `missing` before `silent`. `kind` = `log source` for missing, `rule` for silent. `fix`
comes from a small table keyed by tool/event (put it in `data/gap_fixes.yaml`).

Offline mode: `aphasia detect --from-file deploy/wazuh/samples/indexer_search_response.json` for tests
and for a no-network demo fallback.

## 6. TUI (`aphasia tui`)

Starter shell is provided (`engine/src/aphasia/tui/`). Layout, theme and navigation are done;
it runs on `demo_run.json`. Work left:

| Item | Detail |
|---|---|
| CLI | `aphasia tui [--run runs/<id>] [--demo]`; default = latest run that has `run_view.json`, else demo |
| `r` run | start `run_all` in a Textual worker (`@work(thread=True)`); stream steps into ACTIVITY live |
| `w` wazuh | run detect in a worker; refresh all panels; status bar shows `● wazuh` green/red by reachability |
| `f` filter | Steps table: toggle "silent + missing only" |
| `e` export | write `gaps.md` + keep existing `report.html` |
| `enter` | Scen list → jump to Steps filtered by scenario; Paths list → focus chain |
| Resize | panels must not overflow at 100×30; columns truncate with ellipsis |
| Tests | `tests/test_tui.py` (exists) + one test per key action using `App.run_test()` |

Sections: `1 Work · 2 Scen · 3 Steps · 4 Paths · 5 Map · 6 Gaps · 7 Trace` (Trace: proxy mode). See `docs/TUI_STYLE.md`.

## 7. Acceptance (demo-ready)

- [ ] `uv run python -m pytest -q` green (existing 81 + new).
- [ ] `docker compose -f fixture/docker-compose.yml up -d` then `aphasia run --mode seed` writes `fixture/logs/fixture.jsonl`.
- [ ] Wazuh dashboard shows rule 100210, 100240, 100230 alerts for the run.
- [ ] `aphasia detect --run runs/<id> --insecure` gives ≥3 detected, ≥3 silent, ≥1 missing.
- [ ] `aphasia tui` shows the real run on all 6 sections; `r` then `w` works live in under 60 s.
- [ ] Offline fallback: `aphasia tui --demo` works with the network off.
- [ ] Proxy mode: `aphasia proxy start` + lab LLM agent; `aphasia run --proxy runs/proxy` fills `7 Trace`
      and fires at least 100320 and 100340 in Wazuh.
- [ ] Backup screen recording of the full flow (both modes).

## 9. Proxy mode (`aphasia proxy`)

Verified on 27 Nov 2026: LiteLLM proxy 1.111.0 with the recorder callback logs OpenAI
`/v1/chat/completions` (normal and streaming), Anthropic `/v1/messages`, tool definitions,
tool results in context, and model tool calls (tested against a fake provider).

**Dependency rule:** `litellm[proxy]` pins `rich<14`; Textual 8 needs `rich>=14.2`. They cannot share
an environment. The proxy always runs in its own isolated env via
`uvx --from "litellm[proxy]==1.111.0" litellm ...`. Never add `litellm[proxy]` to engine dependencies.
The recorder (`aphasia/proxy/recorder.py`, provided, tested) imports only stdlib + `litellm`, so it is
copied next to the generated config and loaded as `aphasia_recorder.recorder`.

CLI:
```
aphasia proxy start --provider-model ollama_chat/qwen2.5:7b-instruct [--api-base http://127.0.0.1:11434]
                    [--alias agent-model] [--listen 127.0.0.1:4000] [--dir runs/proxy  (relative to engine/)] [--full]
aphasia proxy status | stop
aphasia run --proxy runs/proxy ...        # writes run context for the recorder before each step
```

`start`:
1. Create `--dir` with `config.yaml` (template: `deploy/proxy/litellm_config.template.yaml`) and
   `aphasia_recorder.py` (copied from the package with `importlib.resources`).
2. Read `[upstream]`, `[proxy]` and the secrets `APHASIA_UPSTREAM_API_KEY`, `APHASIA_PROXY_KEY` from
   `aphasia.config` (§12). Setup generates the proxy key (`sk-aphasia-<token_urlsafe(18)>`); `start`
   generates one if missing and saves it to secrets.env. The config references only
   `os.environ/APHASIA_UPSTREAM_API_KEY` and `os.environ/APHASIA_PROXY_KEY`.
3. Spawn the uvx command with a **clean environment built from scratch** (not `os.environ.copy()`):
   `PATH`, `HOME`, `APHASIA_UPSTREAM_API_KEY`, `APHASIA_PROXY_KEY`, `APHASIA_PROXY_LOG=<dir>/proxy.jsonl`,
   `APHASIA_RUN_CONTEXT=<dir>/context.json`, plus proxy vars (`HTTPS_PROXY`, `NO_PROXY`, `SSL_CERT_FILE`)
   if set. This keeps the attacker key and generic `OPENAI_*`/`ANTHROPIC_*` vars out of the proxy.
   pid in `<dir>/proxy.pid`; wait for `/health/liveliness`.
4. Print the agent settings:
   ```
   OpenAI-compatible:    base_url=http://127.0.0.1:4000/v1   api_key=sk-aphasia-…   model=agent-model
   Anthropic-compatible: ANTHROPIC_BASE_URL=http://127.0.0.1:4000   ANTHROPIC_API_KEY=sk-aphasia-…
   ```
5. Binding other than 127.0.0.1 needs `--listen` explicitly and prints a warning (prompts flow through it).

Run context (`<dir>/context.json`), written by `aphasia run --proxy` before each step, removed after the run:
`{"run_id": "...", "scenario": "...", "step": 3, "honey": ["<canary tokens of this scenario>"]}`

Recorder output (`<dir>/proxy.jsonl`), see `recorder.py` docstring:
- `llm_exchange`: flat flags for Wazuh (`injection_in_tool_result`, `honey_in_context`, `honey_in_reply`,
  `desc_changed`, `changed_tools`, `tool_names`, `tool_call_names`, `roles`, `latency_ms`, `session`)
  plus `messages`, `tools`, `tool_calls`, `reply` for the TUI (text clipped at 2000 chars unless `--full`).
- `llm_tool_call`: one per tool call the model requested: `tool`, `args`, `honey`.
- `llm_error`: provider failures.
Session = header `x-aphasia-session`, else request `user`, else LiteLLM trace id.
Tool-description drift (`desc_changed`) is tracked per (session, tool), so two agents with different
tools of the same name do not raise a false rug-pull.

Detect in proxy mode: read `<dir>/proxy.jsonl` locally to build `run_view.exchanges` (shape: see
`demo_run.json`) and include Wazuh rules 1003xx in matching. A step is `detected` if a fixture rule or
a gateway rule fired for it. Put the gateway rule text in the step's `gateway` field.

MCP visibility: the LLM gateway already sees MCP tools as tool definitions + tool results. For
real MCP traffic, LiteLLM also has an MCP gateway (`mcp_servers:` in config). Stretch goal only:
verify in the VM that the recorder receives MCP tool call events before relying on it.

## 10. Lab LLM agent (`fixture/llm-agent/`) for proxy mode

The existing fixture agent is scripted (no LLM), so it never calls an LLM and cannot use the proxy.
Add a small real agent, same safety rules as the fixture (localhost, no exec, no network except the LLM
base URL and the fixture MCP server, all mutating tools mirror-only):

- Flask, same `/chat` and `/seed` contract as `fixture/agent/app.py`, so the engine needs no new connector.
- OpenAI SDK (`openai` package) with `base_url=$OPENAI_BASE_URL` (the proxy), `api_key=$OPENAI_API_KEY`
  (the proxy key), `model=$AGENT_MODEL` (default `agent-model`), `temperature=0`, max 4 tool rounds.
- Tools: `read_inbox`, `read_record`, `search_docs`, `issue_refund` (mutating), `send_email` (mutating),
  plus the fixture MCP server's tools fetched with the MCP client (so a poisoned description reaches the LLM).
- Tools return seeded canary data; mutating ones return a record `{name, args, mutating: true}` and
  never act. Writes the same fixture telemetry (SPEC §3) with `component: "llm-agent"`.
- Sends `x-aphasia-session` header to the proxy.
- Model: `ollama_chat/qwen2.5:7b-instruct` (tool calling, runs on CPU) or a hosted model through the proxy.
  Seeds must be tuned so the main scenarios succeed at temperature 0; record the model and Ollama version.

## 12. Configuration, the two LLMs, and first-run setup (provided, tested)

Code: `aphasia/config.py`, `aphasia/checks.py`, `aphasia/tui/setup.py`, CLI `setup`, `config`, `tui`.

**Two LLMs, never mixed**

| | Attacker LLM | Upstream LLM |
|---|---|---|
| Owner | Aphasia | the agent under test (proxy mode only) |
| Job | plans attack steps (adaptive / hybrid) | answers the agent's requests via the Aphasia proxy |
| Config | `[attacker]` model, api_base, enabled | `[upstream]` model, api_base, enabled |
| Secret | `APHASIA_ATTACKER_API_KEY` | `APHASIA_UPSTREAM_API_KEY` |
| Used by | `LiteLLMProvider` (explicit model, api_base, api_key) | LiteLLM proxy subprocess only (clean env) |
| Through the proxy? | never (checked) | it is behind the proxy |

Existing code before this change: the attacker was set only by `aphasia run --model/--api-base`; keys came
from generic litellm env vars (`OPENAI_API_KEY`…) and the base from `OLLAMA_API_BASE`/`OLLAMA_HOST`. No
config file. In proxy mode those generic vars would be shared by the attacker, the upstream and the
agent; an `OPENAI_BASE_URL` pointing at the proxy would route attacker traffic through the proxy and log
it as agent traffic. Fixed by role-prefixed config and secrets.

**Files** (`$APHASIA_HOME` or `~/.config/aphasia`): `config.toml` (no secrets) and `secrets.env` (0600).
Precedence: CLI flag > `APHASIA_*` env > config file > default. Old flags and `OLLAMA_API_BASE` still work.

**Blocking checks** (`config.problems`):
- attacker `api_base` at the proxy; any of `OPENAI_BASE_URL`, `OPENAI_API_BASE`, `ANTHROPIC_BASE_URL`,
  `ANTHROPIC_API_BASE` in Aphasia's own env pointing at the proxy; upstream `api_base` at the proxy (loop).
  Compared by host + port, with `localhost`, `127.0.0.1`, `0.0.0.0`, `::1` treated as the same host.
- hosted model (no `ollama*/`, `hosted_vllm/`, `lm_studio/`, `llamafile/` prefix and no custom `api_base`)
  without its own role key. Shared `OPENAI_API_KEY`-style variables never count.
- `mode = proxy` with the proxy disabled; missing models; missing target URL.

`aphasia run` without any config keeps the old behaviour (litellm env vars) but prints a warning; once
the proxy is enabled it refuses to run the attacker without `APHASIA_ATTACKER_API_KEY`.
**Warnings** (`config.warnings`): same key for attacker and upstream, same model for both, Wazuh password
missing, TLS verify off.

**Setup wizard** (TUI): opens automatically on first run (no `config.toml`) unless `--demo`; also
`aphasia setup` or key `s`. Steps: 1 Mode · 2 Target · 3 Attacker LLM · 4 Proxy upstream LLM (shows the
base URL, key and model alias to paste into the agent) · 5 SIEM Wazuh · 6 Review & save.
`ctrl+t` tests the current step (target GET, 1-token LLM completion with the explicit role key — never a
shared one, Wazuh `/_cluster/health`), `ctrl+n` next, `ctrl+s` save (blocked while `problems` is non-empty),
`esc` cancel. Secret fields are prefilled only from `secrets.env`; a secret exported in the environment is
used, shown as "set (environment, not saved)", and never copied to disk. `aphasia setup` exits when the
wizard closes (exit code 0 saved, 1 cancelled).

Still to build on top: `aphasia proxy`, `aphasia detect` and `aphasia run --proxy` read these values
from `config.load()` (Wazuh: `[wazuh]` + `APHASIA_WAZUH_PASSWORD`; the earlier `WAZUH_*` env names in §5
become `APHASIA_WAZUH_URL` / `APHASIA_WAZUH_PASSWORD`).

## 13. Technique catalog and scan selection (provided, tested)

Code: `aphasia/data/catalog.yaml` (59 techniques, 12 categories), `aphasia/catalog.py`, CLI `catalog`
and `run --category`, TUI section 8 "Catalog". Sources and attribution: `docs/CREDITS.md`.

**What it is.** A merged, deduplicated taxonomy from AATMF v3, the Arcanum Prompt Injection Taxonomy
and ZeroLeaks — only tactics/techniques/procedures that can be tested against a live agent or its MCP
toolchain. Only taxonomy (names, ids, categories) was taken; no code, payloads or prompts. Each entry
lists the source ids it maps to, one source id to one Aphasia technique (a test enforces this). 5
items are reference-only (`testable: none`: training, supply-chain, infra, human process).

**It is metadata, not a second engine.** Execution still runs the existing scenarios. A technique's
`scenario` field names the scenario that exercises it (or empty = in the taxonomy, scenario still to
build). `catalog.select(choice, available)` maps a scan choice to scenario ids:
- `all` → every registered scenario (unchanged default)
- a category id → that category's scenarios that exist
- a scenario id → itself

**Scan selection** (your ask "choose all, category-wise, as such"):
- `aphasia run --category <id>` — run a whole category (`all`, `prompt_injection`, `evasion`,
  `extraction`, `exfiltration`, `tool_mcp`, `rag_memory`, `multi_turn`, `excessive_agency`,
  `multimodal`, `availability`, `misinformation`). Mutually exclusive with `--scenario`.
- `aphasia run --scenario <id>` (repeatable) — unchanged.
- `aphasia catalog [--category <id>] [--proxy-better]` — print the taxonomy, coverage, proxy hints.
- TUI section 8 lists categories (coloured by proxy strength) and their techniques.

**Proxy mode guidance (highlight, do not enforce).** Each category has `proxy_hint`
(strong / partial / direct / none) and each technique a `proxy_better` flag and a `testable`
(both / direct / proxy / none). `proxy_better` techniques (29 of 59) are clearer in proxy mode because
the gateway sees the context in, the tool definitions and the tool calls; `testable: proxy` (6) need
proxy mode to be judged at all (e.g. tool-call spoofing, history fabrication, CoT spoofing). None of
this blocks direct mode: `catalog.select` returns the scenarios regardless, and direct runs them as a
black box — the TUI/report just note which findings would be sharper under proxy. When building new
scenarios, give proxy-only ones a clear direct-mode fallback or mark them proxy-recommended.

**To extend:** add a scenario in `scenarios.yaml` + payloads, then set the catalog technique's
`scenario` field to it. The catalog's `runnable` count rises automatically; no code change.

## 11. Out of scope (slides only)

CI regression pipeline, adaptive attacker in the live demo (seed mode only on stage), more SIEMs,
attack graph across agents, multi-tenant.
