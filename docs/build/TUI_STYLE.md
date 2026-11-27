# TUI style guide

Visual reference: Darkmoon "Terminal Explorer" screenshots
(https://github.com/ASCIT31/Dark-Moon/tree/master/docs/pics/terminal-explorer).
Darkmoon is AGPL-3.0 and Aphasia is Apache-2.0: **copy the look, never the code or images.**
The starter in `engine/src/aphasia/tui/` is an independent Textual implementation.
Our own rendered screens are in `screens/` of this kit.

## Principles

- Pure black background. Information density over decoration. No emoji, no gradients.
- Monospace grid. Everything aligns to columns.
- Colour carries meaning only (severity, result). Everything else is grey.
- One focused panel at a time, shown by a blue border and blue title.
- Every screen ends with a key hint bar. Every screen starts with a breadcrumb.

## Palette (`tui/palette.py`, mirrored in `theme.tcss`)

| Token | Hex | Use |
|---|---|---|
| BG | `#000000` | screen, panels |
| bar BG | `#111111` | top bar, key bar |
| FG | `#d0d0d0` | body text |
| BRIGHT | `#ffffff` | values, selected row, titles |
| MUTED | `#8a8a8a` | labels, breadcrumb, hints |
| DIM | `#5f5f5f` | empty bar track, connectors |
| border | `#3a3a3a` | unfocused panel border |
| FOCUS | `#6c9bd2` | focused border + title, active tab number |
| selected row | `#1e1e1e` | list/table cursor |
| critical | `#f2473f` | severity, `silent` result |
| high | `#f7931e` | severity, `missing` (no telemetry) |
| medium | `#f5d327` | severity |
| low | `#1fb6c9` | severity, `blocked` |
| detected | `#3fbf6f` | `detected` result, SIEM connected dot |

## Components

| Component | Spec |
|---|---|
| Top bar | `APHASIA` bold · ` 1 Work  2 Scen …` (active: number blue, name bold white on `#2a2a2a`) · right: `live/demo · ● wazuh 4.14.11` |
| Breadcrumb | one muted line: `Section  ›  context · id` |
| KPI row | 4 columns: UPPERCASE muted label / bold value / bar or muted sub-line |
| Bars | `▆` filled cells, `─` dim track. Severity bar = stacked segments. Ratio bar = grey + `NN%` |
| Panel | thin border, title in the top edge in UPPERCASE + count (`SCENARIOS  8`) |
| List row | `■` coloured square · short code · title (ellipsis) · STATUS right-aligned |
| Detail pane | `■ #n of N · SEVERITY · state` / bold title / `Key         value` pairs / UPPERCASE sub-headers |
| Chain walk | boxed steps `┌─ n · tool ─┐`, connector `┆` + result note (`detected · rule 100210 · L12`), `▼` between steps |
| Key bar | bold white key + muted verb pairs: `↑↓ move  enter open  1-6 sections  r run  w wazuh  q quit` |
| Footnote | optional muted line above key bar for disclaimers |
| Setup wizard | own screen, tab shows ` Setup `; left STEPS list with `□ / ✓ / ✗` per step test result; right form: UPPERCASE muted label above each input, dim hint below; inputs black with `#3a3a3a` border, blue when focused; password inputs masked |

## Text rule (bug we already hit)

`Text("x", style=s)` sets the **base** style, so everything appended later inherits it.
Always build with `palette.styled()` / `Text().append(x, style=s)`.

## Size

Design at 120×40. Must stay readable at 100×30 (projector). Test both with `App.run_test(size=...)`.
On stage: terminal font 16–18 pt, dark theme, full screen.
