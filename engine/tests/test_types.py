from aphasia.types import Canary, Observation, Step, ToolCall, Turn


def test_dataclasses():
    assert Turn(role="user", content="hi").role == "user"
    assert Step(kind="send", channel="chat", payload="p").channel == "chat"
    assert Canary(slot="a", token="t").token == "t"
    assert Observation(reply="x", tool_calls=[]).tool_calls == []
    assert ToolCall(name="refund", args={}, mutating=True).mutating is True
