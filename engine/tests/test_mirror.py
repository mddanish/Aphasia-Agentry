from aphasia.canary.mirror import Mirror, MirrorPolicy, classify
from aphasia.types import ToolCall


class Spy:
    def __init__(self):
        self.calls = 0

    def __call__(self, call):
        self.calls += 1
        return "real"


POLICY = MirrorPolicy(mutating_names={"send_email"})


def test_read_only_passes_and_executes():
    call = ToolCall("search", {"q": "x"}, False)
    spy = Spy()
    assert classify(call, POLICY) == "pass"
    r = Mirror(POLICY).route(call, spy)
    assert r.executed and not r.blocked and r.captured is None
    assert spy.calls == 1


def test_mutating_mirrored_never_executed():
    call = ToolCall("send_email", {"to": "a@b"}, True)
    spy = Spy()
    assert classify(call, POLICY) == "mirror"
    r = Mirror(POLICY).route(call, spy)
    assert r.executed is False and r.captured == call and not r.blocked
    assert spy.calls == 0


def test_policy_name_overrides_false_mutating_flag():
    call = ToolCall("send_email", {}, False)
    spy = Spy()
    r = Mirror(POLICY).route(call, spy)
    assert classify(call, POLICY) == "mirror" and spy.calls == 0 and not r.executed


def test_unclassifiable_blocked():
    call = ToolCall("mystery", {}, None)  # side-effect status unknown
    spy = Spy()
    assert classify(call, POLICY) == "block"
    r = Mirror(POLICY).route(call, spy)
    assert r.blocked is True and not r.executed and r.captured is None
    assert spy.calls == 0
