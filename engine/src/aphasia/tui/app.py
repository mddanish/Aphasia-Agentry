"""Aphasia TUI: terminal explorer for canary-proven runs and their SIEM detections.

Sections: 1 Work · 2 Scen · 3 Steps · 4 Paths · 5 Map · 6 Gaps · 7 Trace (proxy mode)
Starter shell: layout, theme and navigation are final; data comes from RunView.
"""
from pathlib import Path

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import ContentSwitcher, DataTable, Label, ListItem, ListView, Static

from aphasia import catalog as tax, config
from aphasia.tui import palette as P
from aphasia.tui.data import RunView, load_demo, load_run
from aphasia.tui.setup import SetupScreen

SECTIONS = [("work", "Work"), ("scen", "Scen"), ("steps", "Steps"),
            ("paths", "Paths"), ("map", "Map"), ("gaps", "Gaps"), ("trace", "Trace"), ("catalog", "Catalog")]

KEYS = {
    "work": [("↑↓", "move"), ("enter", "open"), ("1-8", "sections"), ("r", "run"), ("w", "wazuh"), ("s", "setup"), ("q", "quit")],
    "scen": [("↑↓", "move"), ("enter", "steps"), ("p", "path"), ("esc", "back"), ("q", "quit")],
    "steps": [("↑↓", "move"), ("enter", "alert"), ("f", "filter silent"), ("esc", "back"), ("q", "quit")],
    "paths": [("↑↓", "path"), ("enter", "walk"), ("esc", "back"), ("q", "quit")],
    "map": [("↑↓", "move"), ("enter", "details"), ("esc", "back"), ("q", "quit")],
    "gaps": [("↑↓", "move"), ("enter", "inspect"), ("e", "export"), ("esc", "back"), ("q", "quit")],
    "trace": [("↑↓", "exchange"), ("enter", "full text"), ("esc", "back"), ("q", "quit")],
    "catalog": [("↑↓", "category"), ("enter", "techniques"), ("esc", "back"), ("q", "quit")],
}


def panel(*children, title: str, id: str | None = None, classes: str = "") -> Vertical:
    v = Vertical(*children, classes=f"panel {classes}".strip(), id=id)
    v.border_title = title
    return v


class AphasiaApp(App):
    CSS_PATH = "theme.tcss"
    TITLE = "Aphasia Agentry"
    BINDINGS = [Binding(str(i + 1), f"section('{sid}')", show=False) for i, (sid, _) in enumerate(SECTIONS)] + [
        Binding("q", "quit", show=False),
        Binding("s", "setup", show=False),
        Binding("escape", "section('work')", show=False),
        Binding("tab", "focus_next", show=False),
    ]

    def __init__(self, view: RunView, live: bool = False, setup: bool = False, setup_only: bool = False):
        super().__init__()
        self.view = view
        self.live = live
        self.setup_on_start = setup or setup_only
        self.setup_only = setup_only          # `aphasia setup`: exit when the wizard closes
        self.current = "work"

    # ---------- chrome ----------
    def _tabs(self) -> Text:
        t = Text()
        for i, (sid, name) in enumerate(SECTIONS):
            on = sid == self.current
            style = f"bold {P.BRIGHT} on #2a2a2a" if on else P.MUTED
            t.append(f" {i + 1} ", style=f"{P.FOCUS} on #2a2a2a" if on else P.DIM)
            t.append(f"{name} ", style=style)
        return t

    def _status(self) -> Text:
        mode = "live" if self.live else "demo"
        t = P.styled(f"{mode} · {self.view.deploy_mode} · ", P.MUTED)
        t.append("● ", style=P.RESULT["detected"])
        t.append(self.view.siem, style=P.MUTED)
        return t

    def compose(self) -> ComposeResult:
        with Horizontal(id="topbar"):
            yield Static("APHASIA", id="brand")
            yield Static(self._tabs(), id="tabs")
            yield Static(self._status(), id="status")
        with ContentSwitcher(initial="work", id="body"):
            yield from self._work()
            yield from self._scen()
            yield from self._steps()
            yield from self._paths()
            yield from self._map()
            yield from self._gaps()
            yield from self._trace()
            yield from self._catalog()
        yield Static(P.keybar(KEYS["work"]), id="keybar")

    def action_section(self, sid: str) -> None:
        self.current = sid
        self.query_one("#body", ContentSwitcher).current = sid
        self.query_one("#tabs", Static).update(self._tabs())
        self.query_one("#keybar", Static).update(P.keybar(KEYS[sid]))
        first = self.query_one(f"#{sid}").query("ListView, DataTable")
        if first:
            first.first().focus()

    # ---------- 1 Work ----------
    def _kpis(self) -> Horizontal:
        v = self.view
        sc = v.scenarios
        sev = [(sum(1 for s in sc if s["severity"] == k), P.SEV[k]) for k in P.SEV_ORDER]
        proven = sum(1 for s in sc if s["verdict"] in ("proven", "metered", "mirror_only"))
        det, sil, mis = v.count("result", "detected"), v.count("result", "silent"), v.count("result", "missing")
        attack_steps = det + sil + mis

        def kpi(name, value, line2, colour=P.BRIGHT):
            t = Text.assemble(P.label(name), "\n", (str(value), f"bold {colour}"), "\n", line2)
            return Static(t, classes="kpi")

        pct = P.styled(f"  {round(100 * proven / len(sc))}%", P.MUTED)
        return Horizontal(
            kpi("Scenarios", len(sc), P.segbar(sev)),
            kpi("Proven", proven, P.ratio_bar(proven, len(sc)) + pct),
            kpi("Detected", f"{det}/{attack_steps}", Text(f"{sil} silent · {mis} no telemetry", style=P.MUTED),
                P.RESULT["detected"]),
            kpi("Silent steps", sil + mis, Text("gaps to close", style=P.MUTED), P.SEV["critical"]),
            id="kpis",
        )

    def _scenario_items(self) -> list[ListItem]:
        items = []
        for s in self.view.scenarios:
            t = P.square(P.SEV[s["severity"]])
            t.append(f"{s['owasp']:<6}", style=P.MUTED)
            t.append(f"{s['title'][:34]:<35}")
            t.append(s["verdict"].upper().replace("_", " "), style=P.VERDICT[s["verdict"]])
            items.append(ListItem(Label(t)))
        return items

    def _executive(self) -> Text:
        v = self.view
        det, sil, mis = v.count("result", "detected"), v.count("result", "silent"), v.count("result", "missing")
        t = Text.assemble(("E ", f"bold {P.BRIGHT}"), (f"run {v.run_id}", P.MUTED), "\n")
        t.append("Agents can be hijacked to move money and leak secrets.\n", style=P.FG)
        t.append(f"Target: {v.target} · mode {v.mode} · {v.duration_min} min\n", style=P.MUTED)
        t.append("Proof: canary hits and mirrored tool calls, no LLM judge.\n", style=P.MUTED)
        t.append(f"\nDEFENDER VIEW · {v.siem}\n", style=f"bold {P.MUTED}")
        t.append(f"{det} detected", style=P.RESULT["detected"])
        t.append("  ·  ")
        t.append(f"{sil} silent", style=P.RESULT["silent"])
        t.append("  ·  ")
        t.append(f"{mis} no telemetry", style=P.RESULT["missing"])
        t.append("\n\nTOP GAPS\n", style=f"bold {P.MUTED}")
        for g in v.gaps[:3]:
            t.append(f" {g['rank']} ▶ ", style=P.SEV[g["severity"]])
            t.append(f"{g['title'][:40]}\n")
        return t

    def _activity(self) -> Text:
        t = Text(no_wrap=True, overflow="ellipsis")
        for s in reversed(self.view.steps[-9:]):
            t.append(f"{s['ts']} ", style=P.MUTED)
            t.append_text(P.square(P.RESULT[s["result"]]))
            t.append(f"{s['scenario'][:16]:<17}", style=P.MUTED)
            t.append(f"{s['action'][:26]}\n")
        return t

    def _detection_bars(self) -> Text:
        v = self.view
        rows = [("detected", v.count("result", "detected")), ("silent", v.count("result", "silent")),
                ("no telemetry", v.count("result", "missing"))]
        mx = max(c for _, c in rows) or 1
        t = P.styled("DETECTION PER ATTACK STEP\n", f"bold {P.MUTED}")
        for name, c in rows:
            key = "missing" if name == "no telemetry" else name
            t.append(f"{name:<13}", style=P.FG)
            t.append_text(P.hbar(c, mx, 26, P.RESULT[key]))
            t.append(f" {c:>3}\n", style=f"bold {P.BRIGHT}")
        t.append("\nSEVERITY OF PROVEN SCENARIOS\n", style=f"bold {P.MUTED}")
        sc = [s for s in v.scenarios if s["verdict"] != "not_proven"]
        for k in ("critical", "high", "medium"):
            c = sum(1 for s in sc if s["severity"] == k)
            t.append(f"{k:<13}", style=P.FG)
            t.append_text(P.hbar(c, len(sc), 26, P.SEV[k]))
            t.append(f" {c:>3}\n", style=f"bold {P.BRIGHT}")
        return t

    def _work(self):
        with Vertical(id="work"):
            yield Static("Workspace", classes="crumb")
            yield self._kpis()
            yield Horizontal(
                panel(ListView(*self._scenario_items()), title=f"SCENARIOS  {len(self.view.scenarios)}"),
                Static(classes="gap"),
                panel(VerticalScroll(Static(self._executive(), classes="detail")),
                      title=f"EXECUTIVE · {self.view.run_id}"),
                classes="row")
            yield Static(classes="vgap")
            yield Horizontal(
                panel(VerticalScroll(Static(self._activity(), classes="detail")), title="ACTIVITY  newest first"),
                Static(classes="gap"),
                panel(Static(self._detection_bars(), classes="detail"), title="DEFENDER LOOP  W wazuh"),
                classes="row")

    # ---------- 2 Scenarios ----------
    def _scen(self):
        with Vertical(id="scen"):
            yield Static("Scenarios  ›  run · " + self.view.run_id, classes="crumb")
            yield Horizontal(
                panel(ListView(*self._scenario_items(), id="scen-list"),
                      title=f"SCENARIOS  {len(self.view.scenarios)}"),
                Static(classes="gap"),
                panel(VerticalScroll(Static(self._scen_detail(0), id="scen-detail", classes="detail")),
                      title="SCENARIO"),
                classes="row")

    def _scen_detail(self, i: int) -> Text:
        s = self.view.scenarios[i]
        t = P.square(P.SEV[s["severity"]])
        t.append(f"#{i + 1} of {len(self.view.scenarios)} · {s['severity'].upper()} · {s['verdict']}\n", style=P.MUTED)
        t.append(s["title"] + "\n\n", style=f"bold {P.BRIGHT}")
        for k, val in (("Scenario", s["id"]), ("OWASP LLM", s["owasp"]), ("MITRE ATLAS", s["atlas"]),
                       ("AATMF v3", s["aatmf"]), ("Proof", s["proof"]), ("Fix", s["fix"])):
            t.append(f"{k:<13}", style=P.MUTED)
            t.append(f"{val}\n")
        t.append("\nSTEPS\n", style=f"bold {P.MUTED}")
        for st in self.view.steps_for(s["id"]):
            t.append_text(P.square(P.RESULT[st["result"]]))
            t.append(f"{st['no']}  {st['action'][:40]:<41}", style=P.FG)
            t.append(st["result"].upper() + "\n", style=P.RESULT[st["result"]])
        return t

    # ---------- 3 Steps (defender loop) ----------
    def _steps(self):
        with Vertical(id="steps"):
            yield Static("Defender loop  ›  every attack step vs " + self.view.siem, classes="crumb")
            table = DataTable(id="steps-table", cursor_type="row", zebra_stripes=False)
            yield Horizontal(
                panel(table, title=f"STEPS  {len(self.view.steps)}"),
                Static(classes="gap"),
                panel(VerticalScroll(Static(self._step_detail(0), id="step-detail", classes="detail")),
                      title="ALERT"),
                classes="row")

    def _step_detail(self, i: int) -> Text:
        s = self.view.steps[i]
        t = P.square(P.RESULT[s["result"]])
        t.append(f"{s['scenario']} · step {s['no']} · {s['ts']}\n", style=P.MUTED)
        t.append(s["action"] + "\n\n", style=f"bold {P.BRIGHT}")
        for k, val in (("Tool", s["tool"]), ("Blocked", "yes" if s["blocked"] else "no"),
                       ("Telemetry", "present" if s["telemetry"] else "missing")):
            t.append(f"{k:<11}", style=P.MUTED)
            t.append(f"{val}\n")
        if s.get("gateway"):
            t.append(f"{'Gateway':<11}", style=P.MUTED)
            t.append(s["gateway"] + "\n", style=P.RESULT["detected"])
        t.append(f"{'Result':<11}", style=P.MUTED)
        t.append(s["result"].upper() + "\n", style=f"bold {P.RESULT[s['result']]}")
        a = s.get("alert")
        t.append("\nWAZUH ALERT\n", style=f"bold {P.MUTED}")
        if a:
            t.append(f"rule {a['rule']} · level {a['level']}\n", style=P.BRIGHT)
            t.append(a["desc"] + "\n")
        else:
            t.append("none in window\n", style=P.RESULT["silent"])
        return t

    # ---------- 4 Paths ----------
    def _paths(self):
        with Vertical(id="paths"):
            yield Static("Attack paths  ›  proven chains, step by step", classes="crumb")
            items = []
            for s in self.view.scenarios:
                t = P.square(P.SEV[s["severity"]])
                t.append(f"{s['title'][:26]:<27}")
                t.append("PROVEN" if s["verdict"] != "not_proven" else "NOT PROVEN",
                         style=P.MUTED)
                items.append(ListItem(Label(t)))
            yield Horizontal(
                panel(ListView(*items, id="path-list"), title="PATHS", classes="narrow"),
                Static(classes="gap"),
                panel(VerticalScroll(Static(self._walk(0), id="walk", classes="detail")), title="CHAIN"),
                classes="row")

    def _walk(self, i: int, width: int = 46) -> Text:
        s = self.view.scenarios[i]
        steps = self.view.steps_for(s["id"])
        t = P.styled(s["title"] + "\n\n", f"bold {P.BRIGHT}")
        t.append(f"┆ {s['verdict'].replace('_', ' ').title()} chain", style=f"bold {P.FG}")
        t.append(f"   {len(steps)} steps · {s['owasp']} · {s['atlas']}\n\n", style=P.MUTED)
        for n, st in enumerate(steps):
            head = f" {st['no']} · {st['tool']} "
            t.append("┌─" + head + "─" * (width - len(head) - 3) + "┐\n", style=P.MUTED)
            body = f" {st['action']}"[: width - 4]
            t.append("│", style=P.MUTED)
            t.append("● ", style=P.RESULT[st["result"]])
            t.append(f"{body:<{width - 4}}")
            t.append("│\n", style=P.MUTED)
            t.append("└" + "─" * (width - 2) + "┘\n", style=P.MUTED)
            a = st.get("alert")
            note = {"detected": f"detected · rule {a['rule']} · L{a['level']}" if a else "detected",
                    "silent": "silent · no alert", "missing": "no telemetry",
                    "expected": "benign-looking · no alert expected", "blocked": "blocked by control"}[st["result"]]
            pad = " " * 6
            t.append(f"{pad}┆  ", style=P.DIM)
            t.append(note + "\n", style=P.RESULT[st["result"]])
            if n < len(steps) - 1:
                t.append(f"{pad}▼\n", style=P.DIM)
        t.append("\nImpact proven by canary: ", style=P.MUTED)
        t.append(s["proof"] + "\n")
        return t

    # ---------- 5 Map ----------
    def _map(self):
        with Vertical(id="map"):
            yield Static("Framework mapping  ›  coverage per state", classes="crumb")
            table = DataTable(id="map-table", cursor_type="row")
            yield Horizontal(
                panel(table, title="FRAMEWORKS  techniques per state"),
                Static(classes="gap"),
                panel(VerticalScroll(Static(self._map_detail("owasp"), id="map-detail", classes="detail")),
                      title="CONTROLS"),
                classes="row")
            yield Static("Mapping of tested scenarios only: not an audit or certification.", id="footnote")

    def _map_detail(self, key: str) -> Text:
        names = {"owasp": "OWASP Top 10 for LLM Apps (2025)", "atlas": "MITRE ATLAS", "aatmf": "AATMF v3"}
        t = P.styled(names[key] + "\n\n", f"bold {P.BRIGHT}")
        for s in self.view.scenarios:
            t.append(f"{s[key]:<15}", style=P.FG)
            t.append(f"{s['title'][:36]}\n")
            t.append(f"{'':<15}{s['verdict'].replace('_', ' ')}\n", style=P.VERDICT[s["verdict"]])
        return t

    # ---------- 6 Gaps ----------
    def _gaps(self):
        with Vertical(id="gaps"):
            yield Static("Detection gap plan  ›  run · " + self.view.run_id, classes="crumb")
            yield Static("Prioritised detection gaps", classes="lead-title")
            yield Static(Text(f"{len(self.view.gaps)} gaps · ordered by severity × proof · each one is a step "
                              "the attack completed without an alert", style=P.MUTED), classes="lead")
            table = DataTable(id="gaps-table", cursor_type="row")
            yield Horizontal(
                panel(table, title=f"GAPS  {len(self.view.gaps)}"),
                Static(classes="gap"),
                panel(VerticalScroll(Static(self._gap_detail(0), id="gap-detail", classes="detail")),
                      title="GAP"),
                classes="row")

    def _gap_detail(self, i: int) -> Text:
        g = self.view.gaps[i]
        t = P.square(P.SEV[g["severity"]])
        t.append(f"#{g['rank']} of {len(self.view.gaps)} · {g['severity'].upper()} · {g['kind']}\n", style=P.MUTED)
        t.append(g["title"] + "\n\n", style=f"bold {P.BRIGHT}")
        for k, val in (("Covers", g["covers"]), ("Fix", g["fix"])):
            t.append(f"{k:<9}", style=P.MUTED)
            t.append(f"{val}\n")
        return t

    # ---------- 7 Trace (proxy mode) ----------
    def _trace(self):
        with Vertical(id="trace"):
            ex = self.view.exchanges
            if self.view.deploy_mode != "proxy" or not ex:
                yield Static("LLM trace  ›  proxy mode only", classes="crumb")
                yield Static(P.styled("Direct mode runs the agent as a black box. Start `aphasia proxy` and point "
                                      "the agent's LLM base URL at it to see context in, tool calls out.", P.MUTED),
                             classes="lead")
                return
            yield Static(f"LLM trace  ›  gateway view · {len(ex)} exchanges", classes="crumb")
            items = []
            for e in ex:
                t = P.square(P.SEV["critical"] if e["flags"] else P.RESULT["expected"])
                t.append(f"{e['ts']}  ", style=P.MUTED)
                t.append(f"{e['scenario'][:18]:<19}")
                calls = ",".join(c["name"] for c in e["tool_calls"]) or "reply"
                t.append(calls[:14], style=P.MUTED)
                items.append(ListItem(Label(t)))
            yield Horizontal(
                panel(ListView(*items, id="trace-list"), title=f"EXCHANGES  {len(ex)}", classes="narrow"),
                Static(classes="gap"),
                panel(VerticalScroll(Static(self._trace_detail(0), id="trace-detail", classes="detail")),
                      title="CONTEXT IN  ›  MODEL OUT"),
                classes="row")

    def _trace_detail(self, i: int) -> Text:
        e = self.view.exchanges[i]
        t = P.styled(f"#{e['no']} · {e['scenario']} step {e['step']} · {e['model']} · {e['latency_ms']} ms · "
                     f"session {e['session']}\n", P.MUTED)
        for f in e["flags"]:
            t.append("■ ", style=P.SEV["critical"])
            t.append(f.replace("_", " ") + "  ", style=P.SEV["critical"])
        t.append("\n\nCONTEXT IN\n", style=f"bold {P.MUTED}")
        for m in e["messages"]:
            colour = P.SEV["high"] if m["role"] == "tool" else P.FG
            t.append(f"{m['role']:<10}", style=P.MUTED)
            t.append(m["content"][:300] + "\n", style=colour)
        t.append("\nTOOLS OFFERED\n", style=f"bold {P.MUTED}")
        for d in e["tools"]:
            t.append(f"{d['name']:<16}", style=P.FG)
            t.append(f"{d['desc_hash']}\n", style=P.SEV["critical"] if "changed" in d["desc_hash"] else P.MUTED)
        t.append("\nMODEL OUT\n", style=f"bold {P.MUTED}")
        for c in e["tool_calls"]:
            t.append("▶ ", style=P.SEV["critical"])
            t.append(f"{c['name']}", style=f"bold {P.BRIGHT}")
            t.append(f"({', '.join(f'{k}={v}' for k, v in c['args'].items())})\n")
        if e["reply"]:
            t.append(f"{'reply':<10}", style=P.MUTED)
            t.append(e["reply"][:300] + "\n")
        return t

    # ---------- 8 Catalog (taxonomy, scan selection) ----------
    def _catalog(self):
        cat = tax.load()
        runnable = {s["id"] for s in [{"id": sc["id"]} for sc in []]} or set(self._scenario_ids())
        self._cat_runnable = runnable
        with Vertical(id="catalog"):
            yield Static("Technique catalog  ›  AATMF + Arcanum + ZeroLeaks, deduplicated", classes="crumb")
            items = []
            for c in cat.categories:
                techs = cat.in_category(c.id)
                runs = sum(1 for t in techs if t.scenario in runnable)
                colour = {"strong": P.RESULT["detected"], "partial": P.SEV["medium"],
                          "direct": P.MUTED, "none": P.DIM}[c.proxy_hint]
                t = P.square(colour)
                t.append(f"{c.name[:27]:<28}")
                t.append(f"{len(techs):>2}t {runs:>2}r", style=P.MUTED)
                items.append(ListItem(Label(t)))
            yield Horizontal(
                panel(ListView(*items, id="cat-list"), title=f"CATEGORIES  {len(cat.categories)}",
                      classes="narrow"),
                Static(classes="gap"),
                panel(VerticalScroll(Static(self._cat_detail(0), id="cat-detail", classes="detail")),
                      title="TECHNIQUES"),
                classes="row")
            yield Static(Text("proxy: ", style=P.MUTED) + P.styled("strong ", P.RESULT["detected"])
                         + P.styled("partial ", P.SEV["medium"]) + P.styled("direct-ok ", P.MUTED)
                         + Text("· run a group with ", style=P.MUTED)
                         + P.styled("aphasia run --category <id>", P.BRIGHT), id="footnote")

    def _scenario_ids(self) -> set:
        return {s["id"] for s in self.view.scenarios}

    def _cat_detail(self, i: int) -> Text:
        cat = tax.load()
        c = cat.categories[i]
        runnable = getattr(self, "_cat_runnable", self._scenario_ids())
        t = P.styled(f"{c.name}  ·  proxy {c.proxy_hint}\n", f"bold {P.BRIGHT}")
        t.append(f"run: aphasia run --category {c.id}\n\n", style=P.MUTED)
        for tk in cat.in_category(c.id):
            runs = tk.scenario in runnable
            mark = "●" if runs else ("·" if tk.testable == "none" else "○")
            t.append(f"{mark} ", style=P.RESULT["detected"] if runs else P.DIM)
            t.append(f"{tk.id} ", style=P.MUTED)
            t.append(f"{tk.name[:36]:<37}")
            if tk.proxy_better:
                t.append("proxy+ ", style=P.SEV["medium"])
            t.append(f"{tk.owasp}\n", style=P.MUTED)
            srcs = " ".join(f"{k}:{v}" for k, v in tk.sources.items() if v)
            t.append(f"    {srcs}\n", style=P.DIM)
        t.append("\n● runs now   ○ in taxonomy, scenario to build   · reference only\n", style=P.MUTED)
        return t

    # ---------- wiring ----------
    def on_mount(self) -> None:
        st = self.query_one("#steps-table", DataTable)
        st.add_columns("#", "SCENARIO", "ACTION", "TEL", "ALERT", "RESULT")
        for s in self.view.steps:
            st.add_row(str(s["no"]), s["scenario"][:14], s["action"][:22], "✓" if s["telemetry"] else "—",
                       s["alert"]["rule"] if s.get("alert") else "—",
                       Text(s["result"].upper(), style=P.RESULT[s["result"]]))
        mt = self.query_one("#map-table", DataTable)
        mt.add_columns("FRAMEWORK", "PROVEN", "NOT", "N/T")
        sc = self.view.scenarios
        prov = sum(1 for s in sc if s["verdict"] != "not_proven")
        for key, name, total in (("owasp", "OWASP LLM Top 10 (2025)", 10), ("atlas", "MITRE ATLAS", len(sc)),
                                 ("aatmf", "AATMF v3 (T11/T12/T13)", len(sc))):
            mt.add_row(P.styled("■ ", P.FG) + Text(name), str(prov), str(len(sc) - prov),
                       str(max(total - len(sc), 0)), key=key)
        gt = self.query_one("#gaps-table", DataTable)
        gt.add_columns("#", "GAP", "TYPE")
        for g in self.view.gaps:
            gt.add_row(P.styled("▶ ", P.SEV[g["severity"]]) + Text(str(g["rank"])), g["title"][:30], g["kind"])
        self.query_one("#work ListView", ListView).focus()
        if self.setup_on_start:
            self.action_setup()

    def action_setup(self) -> None:
        if not isinstance(self.screen, SetupScreen):
            self.push_screen(SetupScreen(first_run=config.is_first_run()), self._after_setup)

    def _after_setup(self, cfg) -> None:
        if self.setup_only:
            self.exit(0 if cfg is not None else 1)
            return
        if cfg is not None:
            self.view.deploy_mode = cfg.mode
            self.query_one("#status", Static).update(self._status())

    def on_list_view_highlighted(self, ev: ListView.Highlighted) -> None:
        i = ev.list_view.index or 0
        if ev.list_view.id == "scen-list":
            self.query_one("#scen-detail", Static).update(self._scen_detail(i))
        elif ev.list_view.id == "path-list":
            self.query_one("#walk", Static).update(self._walk(i))
        elif ev.list_view.id == "trace-list":
            self.query_one("#trace-detail", Static).update(self._trace_detail(i))
        elif ev.list_view.id == "cat-list":
            self.query_one("#cat-detail", Static).update(self._cat_detail(i))

    def on_data_table_row_highlighted(self, ev: DataTable.RowHighlighted) -> None:
        i = ev.cursor_row
        if ev.data_table.id == "steps-table":
            self.query_one("#step-detail", Static).update(self._step_detail(i))
        elif ev.data_table.id == "gaps-table":
            self.query_one("#gap-detail", Static).update(self._gap_detail(i))
        elif ev.data_table.id == "map-table" and ev.row_key.value:
            self.query_one("#map-detail", Static).update(self._map_detail(ev.row_key.value))


def run_tui(run_dir: str | None = None, demo: bool = False, setup: bool = False,
            setup_only: bool = False) -> int:
    """Open the TUI. Setup opens first when asked, or on first run (no config.toml) unless --demo."""
    view = load_run(Path(run_dir)) if run_dir else load_demo()
    show_setup = setup or (not demo and config.is_first_run())
    rc = AphasiaApp(view, live=bool(run_dir), setup=show_setup, setup_only=setup_only).run()
    return rc or 0


if __name__ == "__main__":
    run_tui()
