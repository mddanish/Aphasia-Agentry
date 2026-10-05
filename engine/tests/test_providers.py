import pytest

from aphasia.providers import LiteLLMProvider, ProviderError, StubProvider
from aphasia.types import Step, Turn


def test_stub_yields_in_order():
    s1, s2 = Step("say", "direct", "a"), Step("say", "direct", "b")
    p = StubProvider([s1, s2])
    assert p.plan("g", []) is s1
    assert p.plan("g", []) is s2


def test_stub_exhausted_raises_provider_error():
    with pytest.raises(ProviderError):
        StubProvider([]).plan("g", [])


def test_litellm_parses_completion_to_step(monkeypatch):
    import litellm
    seen = {}

    def fake_completion(**kw):
        seen.update(kw)
        return {"choices": [{"message": {"content": "ATTACK PAYLOAD"}}]}

    monkeypatch.setattr(litellm, "completion", fake_completion)
    step = LiteLLMProvider("gpt-4o-mini").plan("goal", [Turn("assistant", "prior")])
    assert step.payload == "ATTACK PAYLOAD" and step.kind == "say"
    assert seen["model"] == "gpt-4o-mini"
    # goal is appended as the final user message; history precedes it
    assert seen["messages"][0] == {"role": "assistant", "content": "prior"}
    assert seen["messages"][-1] == {"role": "user", "content": "goal"}


def test_litellm_api_base_passed_through(monkeypatch):
    import litellm
    seen = {}
    monkeypatch.setattr(litellm, "completion",
                        lambda **kw: seen.update(kw) or {"choices": [{"message": {"content": "x"}}]})
    LiteLLMProvider("ollama/llama3.2:1b", api_base="http://host:11434").plan("g", [])
    assert seen["api_base"] == "http://host:11434"


def test_litellm_error_wrapped_as_provider_error(monkeypatch):
    import litellm

    def boom(**kw):
        raise RuntimeError("backend down")

    monkeypatch.setattr(litellm, "completion", boom)
    with pytest.raises(ProviderError):
        LiteLLMProvider("gpt-4o-mini").plan("g", [])


def test_litellm_empty_content_raises(monkeypatch):
    import litellm
    monkeypatch.setattr(litellm, "completion",
                        lambda **kw: {"choices": [{"message": {"content": ""}}]})
    with pytest.raises(ProviderError):
        LiteLLMProvider("gpt-4o-mini").plan("g", [])
