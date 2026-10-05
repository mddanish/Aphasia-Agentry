from aphasia.connectors import ConnectorError
from aphasia.evidence import EvidenceStore
from aphasia.providers import StubProvider
from aphasia.run import KillSwitch, run_all, run_scenario, ScenarioResult
from aphasia.scenarios import Scenario
from aphasia.types import Observation, Step, ToolCall
from aphasia.attacker import Attacker
from aphasia.canary.mirror import Mirror, MirrorPolicy


def sc(id="s"):
    return Scenario(id=id, category="c", channel="direct", goal="g",
                    success_condition="x", atlas="a", owasp="o")


class FakeConnector:
    host = "fake-host"
    identity = "fake-id"

    def __init__(self, reply=None, tool_calls=(), echo_after=None):
        self.canaries, self.reply, self.tool_calls = [], reply, list(tool_calls)
        self.echo_after, self.n = echo_after, 0
        self.channels = []

    def plant(self, canaries):
        self.canaries = canaries

    def deliver(self, step):
        self.n += 1
        self.channels.append(step.channel)
        reply = self.reply or "ok"
        if self.echo_after and self.n >= self.echo_after:
            reply = f"leak {self.canaries[0].token}"
        return Observation(reply=reply, tool_calls=self.tool_calls)


def steps(n):
    return [Step("say", "other", f"p{n_}") for n_ in range(n)]


def _run(conn, n_steps, max_steps, tmp_path):
    from aphasia.canary.tokens import mint
    store = EvidenceStore(tmp_path)
    canaries = mint(b"k", "r1", "s", ["record", "token", "beacon"])
    res = run_scenario(sc(), conn, Attacker(StubProvider(steps(n_steps))), canaries,
                       Mirror(MirrorPolicy(set())), store, "r1", max_steps)
    return res, store.read()


def test_self_check_success(tmp_path):
    conn = FakeConnector(echo_after=2)
    res, rows = _run(conn, 5, 6, tmp_path)
    assert res.verdict == "success" and res.steps == 2 and res.hit_canaries
    assert rows[-1]["canary_hits"]
    assert set(rows[-1]) == {"run_id", "step_no", "ts", "target_host", "target_identity",
                             "channel", "payload", "observation", "tool_calls",
                             "canary_hits", "verdict", "scenario_id"}
    assert conn.channels == ["direct", "direct"]  # scenario channel stamped


def test_cap(tmp_path):
    res, rows = _run(FakeConnector(), 5, 2, tmp_path)
    assert res.verdict == "capped" and len(rows) == 2


def test_error_isolation(tmp_path):
    class Conn2(FakeConnector):
        calls = 0

        def deliver(self, step):
            Conn2.calls += 1
            if Conn2.calls == 1:
                raise ConnectorError("down")
            return Observation("ok", [])

    out = run_all([sc("A"), sc("B")], Conn2(), StubProvider(steps(10)),
                  tmp_path, max_steps=2)
    assert [r.verdict for r in out.results] == ["error", "capped"]
    assert any(r["verdict"] == "error" for r in EvidenceStore(tmp_path).read())


def test_mirror_only(tmp_path):
    tc = ToolCall("send_email", {"to": "x"}, True)
    res, _ = _run(FakeConnector(tool_calls=[tc]), 3, 2, tmp_path)
    assert res.verdict == "mirror_only"


def test_killswitch_halts_run(tmp_path):
    class Conn(FakeConnector):
        def deliver(self, step):
            raise KillSwitch()

    out = run_all([sc("A"), sc("B")], Conn(), StubProvider(steps(10)), tmp_path)
    assert out.results == []


def test_plant_error_isolated(tmp_path):
    class Conn(FakeConnector):
        planted = 0

        def plant(self, canaries):
            Conn.planted += 1
            if Conn.planted == 1:
                raise ConnectorError("plant down")

    out = run_all([sc("A"), sc("B")], Conn(), StubProvider(steps(10)), tmp_path, max_steps=2)
    assert [r.verdict for r in out.results] == ["error", "capped"]
    assert out.results[0].steps == 0


def test_metered_on_cost_breach(tmp_path):
    # FakeConnector replies carry a cost marker; cumulative cost crosses the cap -> metered.
    conn = FakeConnector(reply="generating... [[COST:120000]]")
    res, rows = _run(conn, 6, 6, tmp_path)
    assert res.verdict == "metered" and res.steps == 1


def test_no_metered_below_cap(tmp_path):
    conn = FakeConnector(reply="generating... [[COST:10]]")  # tiny cost, never breaches
    res, rows = _run(conn, 6, 6, tmp_path)
    assert res.verdict in ("clean", "capped")  # not metered


def test_seed_mode_run_without_provider(tmp_path):
    # The fake connector echoes the delivered payload; a seed carrying the canary -> success,
    # proving a full run works in seed mode with provider=None (no LLM).
    from aphasia.canary.tokens import mint
    canaries = mint(b"k", "r1", "s", ["record", "token", "beacon"])
    tok = canaries[0].token

    class EchoConn:
        host, identity = "h", "i"
        def plant(self, c): pass
        def deliver(self, step):
            return Observation(reply=f"leaked {step.payload}", tool_calls=[])

    store = EvidenceStore(tmp_path)
    att = Attacker(provider=None, payloads=[f"use {tok}"], mode="seed")
    res = run_scenario(sc(), EchoConn(), att, canaries, Mirror(MirrorPolicy(set())),
                       store, "r1", max_steps=6)
    assert res.verdict == "success" and res.steps == 1
