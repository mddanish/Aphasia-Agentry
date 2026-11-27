# Expected wazuh-logtest results for samples/telemetry.jsonl

| Line | Event | Expected rule | Level |
|---|---|---|---|
| 1 | inbound email | 100201 | 3 (telemetry only) |
| 2 | issue_refund to unseen payee | 100210 | 12 |
| 3 | send_email to unknown recipient | 100240 | 10 |
| 4 | MCP description changed | 100230 | 10 |
| 5 | mutating call after 100230, same session | 100260 | 14 (only if line 4 was seen in the last 300 s) |
| 6 | read_record on honey record | 100205 | 3 (deliberately silent) |
| 7 | generation over budget | 100250 | 8 |

Paste each line into `/var/ossec/bin/wazuh-logtest` inside the manager container.
If a different sibling rule wins, reorder the children in aphasia_rules.xml (first match wins).

## Proxy mode lines (8–10)

| Line | Event | Expected rule | Level |
|---|---|---|---|
| 8 | exchange with injection in tool output | 100320 | 10 |
| 9 | LLM tool call with honey token | 100310 | 13 |
| 10 | honey credential in LLM reply | 100340 | 12 |
