"""Initial setup wizard (first run, or `aphasia setup`, or key `s`).

Writes ~/.config/aphasia/config.toml and secrets.env (0600) via aphasia.config.
Keeps the two LLMs visibly separate: ATTACKER (Aphasia's own) and UPSTREAM (proxy mode, serves
the agent under test).
"""
import os
import secrets as pysecrets

from rich.text import Text
from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import ContentSwitcher, Input, Label, ListItem, ListView, Select, Static, Switch

from aphasia import checks, config
from aphasia.tui import palette as P

STEPS = [("mode", "Mode"), ("target", "Target"), ("attacker", "Attacker LLM"),
         ("upstream", "Proxy upstream LLM"), ("wazuh", "SIEM · Wazuh"), ("review", "Review & save")]

HELP = {
    "mode": "Direct: Aphasia attacks the agent as a black box.\n"
            "Proxy: Aphasia also runs an LLM gateway. The agent under test uses its base URL and key; "
            "the real provider (upstream) is configured here. Aphasia then sees context in, tool calls out.",
    "target": "The agent under test. 'fixture' is the bundled vulnerable agent on 127.0.0.1:8000.",
    "attacker": "Aphasia's OWN LLM. Plans attack steps in adaptive/hybrid mode. Leave off for seed mode "
                "(no LLM). It talks to its provider directly and never goes through the Aphasia proxy.",
    "upstream": "Proxy mode only. The real provider behind the Aphasia proxy, used by the AGENT UNDER TEST. "
                "Separate model, base URL and key from the attacker.",
    "wazuh": "Wazuh indexer (OpenSearch API, port 9200) used by `aphasia detect`.",
    "review": "Check, then save with ctrl+s. Secrets go to secrets.env (0600), never to config.toml.",
}


def secret_input(cfg: config.Config, name: str, wid: str) -> Input:
    """Password input prefilled only from secrets.env. A value exported in the environment is never
    copied into the form (and so never written to disk); the placeholder says it is in use."""
    hint = (f"set via environment ${name} (used; leave empty to keep it out of secrets.env)"
            if os.environ.get(name) else f"stored as {name} in secrets.env")
    return Input(cfg.secrets.get(name, ""), password=True, placeholder=hint, id=wid)


def field_row(label: str, widget, hint: str = "") -> Vertical:
    parts = [Label(Text(label.upper(), style=P.MUTED), classes="flabel"), widget]
    if hint:
        parts.append(Label(Text(hint, style=P.DIM), classes="fhint"))
    return Vertical(*parts, classes="frow")


class SetupScreen(Screen):
    BINDINGS = [
        Binding("ctrl+s", "save", "save"),
        Binding("ctrl+t", "test", "test"),
        Binding("ctrl+n", "next_step", "next", show=False),
        Binding("escape", "cancel", "cancel"),
    ]

    def __init__(self, first_run: bool):
        super().__init__(id="setup")
        self.first_run = first_run
        self.cfg = config.load()
        self.results: dict[str, tuple[bool, str]] = {}

    # ---------- layout ----------
    def compose(self) -> ComposeResult:
        c = self.cfg
        with Horizontal(id="topbar"):
            yield Static("APHASIA", id="brand")
            yield Static(P.styled(" Setup ", f"bold {P.BRIGHT} on #2a2a2a"), id="tabs")
            yield Static(P.styled(f"config · {config.home()}", P.MUTED), id="status")
        yield Static("Initial setup  ›  instance" + ("  ·  first run" if self.first_run else ""), classes="crumb")
        with Horizontal(classes="row"):
            steps = ListView(*[ListItem(Label(self._step_label(i))) for i in range(len(STEPS))], id="steps-nav")
            p = Vertical(steps, Static(id="checks", classes="detail"), classes="panel narrow")
            p.border_title = f"STEPS  {len(STEPS)}"
            yield p
            yield Static(classes="gap")
            form = Vertical(classes="panel")
            form.border_title = "MODE"
            with form:
                yield Static(id="help", classes="detail")
                with ContentSwitcher(initial="f-mode", id="forms"):
                    with VerticalScroll(id="f-mode"):
                        yield field_row("Default mode", Select([("direct · black box", "direct"),
                                                                ("proxy · LLM gateway in the path", "proxy")],
                                                               value=c.mode, allow_blank=False, id="mode"))
                    with VerticalScroll(id="f-target"):
                        yield field_row("Target kind", Select([("fixture (bundled, localhost)", "fixture"),
                                                               ("HTTP chat endpoint", "http"),
                                                               ("MCP endpoint", "mcp")],
                                                              value=c.target.kind, allow_blank=False, id="t-kind"))
                        yield field_row("URL", Input(c.target.url, placeholder="http://127.0.0.1:8002/chat",
                                                     id="t-url"), "empty for fixture")
                    with VerticalScroll(id="f-attacker"):
                        yield field_row("Enabled", Switch(c.attacker.enabled, id="a-on"), "off = seed mode only")
                        yield field_row("Model", Input(c.attacker.model, placeholder="gpt-4o-mini · "
                                                       "anthropic/claude-3-5-haiku · ollama/llama3.2:3b", id="a-model"))
                        yield field_row("API base", Input(c.attacker.api_base,
                                                          placeholder="only for Ollama / vLLM", id="a-base"))
                        yield field_row("API key", secret_input(c, config.ATTACKER_KEY, "a-key"))
                    with VerticalScroll(id="f-upstream"):
                        yield field_row("Proxy enabled", Switch(c.proxy.enabled, id="u-on"))
                        yield field_row("Upstream model", Input(c.upstream.model,
                                                                placeholder="ollama_chat/qwen2.5:7b-instruct",
                                                                id="u-model"))
                        yield field_row("Upstream API base", Input(c.upstream.api_base,
                                                                   placeholder="http://127.0.0.1:11434", id="u-base"))
                        yield field_row("Upstream API key", secret_input(c, config.UPSTREAM_KEY, "u-key"))
                        yield field_row("Listen", Input(c.proxy.listen, id="u-listen"), "keep 127.0.0.1 unless the "
                                        "agent runs on another host")
                        yield field_row("Model alias for the agent", Input(c.proxy.alias, id="u-alias"))
                        yield Static(id="agent-settings", classes="detail")
                    with VerticalScroll(id="f-wazuh"):
                        yield field_row("Enabled", Switch(c.wazuh.enabled, id="w-on"))
                        yield field_row("Indexer URL", Input(c.wazuh.indexer_url,
                                                             placeholder="https://<vm>:9200", id="w-url"))
                        yield field_row("User", Input(c.wazuh.user, id="w-user"))
                        yield field_row("Password", secret_input(c, config.WAZUH_PASSWORD, "w-pass"))
                        yield field_row("CA certificate", Input(c.wazuh.ca_cert,
                                                                placeholder=".../root-ca.pem", id="w-ca"))
                        yield field_row("Skip TLS verify (lab only)", Switch(c.wazuh.insecure, id="w-insecure"))
                    with VerticalScroll(id="f-review"):
                        yield Static(id="review", classes="detail")
            yield form
        yield Static(P.keybar([("↑↓", "step"), ("tab", "field"), ("ctrl+t", "test"), ("ctrl+n", "next"),
                               ("ctrl+s", "save"), ("esc", "cancel")]), id="keybar")

    def on_mount(self) -> None:
        self.query_one("#steps-nav", ListView).focus()
        self._show(0)

    # ---------- state ----------
    def _step_label(self, i: int) -> Text:
        sid, name = STEPS[i]
        res = getattr(self, "results", {}).get(sid)
        mark, colour = ("□", P.MUTED) if res is None else (("✓", P.RESULT["detected"]) if res[0]
                                                            else ("✗", P.SEV["critical"]))
        t = P.styled(f"{mark} ", colour)
        t.append(f"{i + 1}  {name}")
        return t

    def _show(self, i: int) -> None:
        sid = STEPS[i][0]
        self.current = sid
        self.query_one("#forms", ContentSwitcher).current = f"f-{sid}"
        self.query_one("#forms").parent.border_title = STEPS[i][1].upper()
        self.query_one("#help", Static).update(P.styled(HELP[sid] + "\n", P.MUTED))
        if sid == "upstream":
            self._agent_settings()
        if sid == "review":
            self.query_one("#review", Static).update(self._review())

    def on_list_view_highlighted(self, ev: ListView.Highlighted) -> None:
        if ev.list_view.id == "steps-nav":
            self._show(ev.list_view.index or 0)

    def action_next_step(self) -> None:
        nav = self.query_one("#steps-nav", ListView)
        nav.index = min((nav.index or 0) + 1, len(STEPS) - 1)

    # ---------- collect ----------
    def _val(self, wid: str):
        return self.query_one(f"#{wid}").value

    def collect(self) -> config.Config:
        c = config.Config()
        c.mode = self._val("mode")
        c.target = config.TargetCfg(kind=self._val("t-kind"), url=self._val("t-url").strip())
        c.attacker = config.LLMCfg(model=self._val("a-model").strip(), api_base=self._val("a-base").strip(),
                                   enabled=self._val("a-on"))
        c.upstream = config.LLMCfg(model=self._val("u-model").strip(), api_base=self._val("u-base").strip(),
                                   enabled=self._val("u-on"))
        c.proxy = config.ProxyCfg(enabled=self._val("u-on"), listen=self._val("u-listen").strip() or "127.0.0.1:4000",
                                  alias=self._val("u-alias").strip() or "agent-model", dir=self.cfg.proxy.dir,
                                  full_text=self.cfg.proxy.full_text)
        c.wazuh = config.WazuhCfg(enabled=self._val("w-on"), indexer_url=self._val("w-url").strip(),
                                  user=self._val("w-user").strip() or "admin", ca_cert=self._val("w-ca").strip(),
                                  insecure=self._val("w-insecure"))
        proxy_key = self.cfg.secrets.get(config.PROXY_KEY, "")       # file value only, never env
        if c.proxy.enabled and not proxy_key and not os.environ.get(config.PROXY_KEY):
            proxy_key = "sk-aphasia-" + pysecrets.token_urlsafe(18)
            self.cfg.secrets[config.PROXY_KEY] = proxy_key
        c.secrets = {config.ATTACKER_KEY: self._val("a-key"), config.UPSTREAM_KEY: self._val("u-key"),
                     config.WAZUH_PASSWORD: self._val("w-pass"), config.PROXY_KEY: proxy_key}
        return c

    # ---------- views ----------
    def _agent_settings(self) -> None:
        c = self.collect()
        key = c.secret(config.PROXY_KEY) or "(generated on save)"
        t = P.styled("\nAGENT UNDER TEST SETTINGS (copy into the agent)\n", f"bold {P.MUTED}")
        if not c.proxy.enabled:
            t.append("proxy disabled\n", style=P.DIM)
        else:
            for k, v in (("OpenAI base_url", f"{c.proxy.url}/v1"), ("Anthropic base", c.proxy.url),
                         ("api_key", key), ("model", c.proxy.alias)):
                t.append(f"{k:<17}", style=P.MUTED)
                t.append(f"{v}\n", style=P.BRIGHT)
        self.query_one("#agent-settings", Static).update(t)

    def _review(self) -> Text:
        c = self.collect()
        t = P.styled("", "")
        rows = [("Mode", c.mode), ("Target", c.target.kind + (f" · {c.target.url}" if c.target.url else "")),
                ("Attacker LLM", (c.attacker.model or "-") if c.attacker.enabled else "off (seed only)"),
                ("Upstream LLM", (c.upstream.model or "-") if c.proxy.enabled else "off (direct only)"),
                ("Proxy", c.proxy.url if c.proxy.enabled else "off"),
                ("Wazuh", c.wazuh.indexer_url if c.wazuh.enabled else "off")]
        for k, v in rows:
            t.append(f"{k:<15}", style=P.MUTED)
            t.append(f"{v}\n", style=P.BRIGHT)
        t.append("\nSECRETS\n", style=f"bold {P.MUTED}")
        for k in config.SECRET_NAMES:
            t.append(f"{k:<27}", style=P.MUTED)
            src = c.secret_source(k)
            t.append((f"set ({'environment, not saved' if src == 'env' else 'secrets.env'})" if src
                      else "not set") + "\n")
        probs, warns = config.problems(c), config.warnings(c)
        t.append("\nCHECKS\n", style=f"bold {P.MUTED}")
        for p in probs:
            t.append("✗ " + p + "\n", style=P.SEV["critical"])
        for w in warns:
            t.append("! " + w + "\n", style=P.SEV["medium"])
        if not probs and not warns:
            t.append("✓ no problems\n", style=P.RESULT["detected"])
        return t

    def _refresh_checks(self) -> None:
        nav = self.query_one("#steps-nav", ListView)
        for i, item in enumerate(nav.children):
            item.query_one(Label).update(self._step_label(i))
        t = P.styled("\n", "")
        for sid, (ok, msg) in self.results.items():
            t.append("✓ " if ok else "✗ ", style=P.RESULT["detected"] if ok else P.SEV["critical"])
            t.append(f"{sid}: {msg[:60]}\n", style=P.MUTED)
        self.query_one("#checks", Static).update(t)

    # ---------- actions ----------
    def action_test(self) -> None:
        self._run_check(self.current, self.collect())

    @work(thread=True, exclusive=True)
    def _run_check(self, sid: str, c: config.Config) -> None:
        if sid == "target":
            res = checks.target(c.target.kind, c.target.url)
        elif sid == "attacker":
            res = checks.llm(c.attacker.model, c.attacker.api_base, c.secret(config.ATTACKER_KEY)) \
                if c.attacker.enabled else (True, "off (seed mode)")
        elif sid == "upstream":
            res = checks.llm(c.upstream.model, c.upstream.api_base, c.secret(config.UPSTREAM_KEY)) \
                if c.proxy.enabled else (True, "off (direct mode)")
        elif sid == "wazuh":
            res = checks.wazuh(c.wazuh.indexer_url, c.wazuh.user, c.secret(config.WAZUH_PASSWORD),
                               c.wazuh.ca_cert, c.wazuh.insecure) if c.wazuh.enabled else (True, "off")
        else:
            res = (not config.problems(c), "config valid" if not config.problems(c) else "see review")
        self.results[sid] = res
        self.app.call_from_thread(self._refresh_checks)

    def action_save(self) -> None:
        c = self.collect()
        probs = config.problems(c)
        if probs:
            self.notify("Not saved: " + probs[0], severity="error", timeout=6)
            self.query_one("#steps-nav", ListView).index = len(STEPS) - 1
            return
        path = config.save(c)
        self.notify(f"Saved to {path}", timeout=4)
        self.dismiss(c)

    def action_cancel(self) -> None:
        if self.first_run:
            self.notify("Setup not saved. Run `aphasia setup` or press s later.", timeout=4)
        self.dismiss(None)
