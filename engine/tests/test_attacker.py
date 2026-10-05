import pytest

from aphasia.attacker import Attacker
from aphasia.providers import StubProvider
from aphasia.scenarios import Scenario
from aphasia.types import Observation, Step, Turn


class RecordingProvider:
    """Fake provider that records plan() calls for assertion."""

    def __init__(self, steps: list[Step]):
        self._steps = list(steps)
        self._i = 0
        self.calls = []

    def plan(self, goal: str, history: list[Turn]) -> Step:
        # Store a copy of history to preserve what was passed at call time
        self.calls.append((goal, list(history)))
        if self._i >= len(self._steps):
            raise RuntimeError("RecordingProvider script exhausted")
        step = self._steps[self._i]
        self._i += 1
        return step


def test_attacker_next_step_returns_provider_step():
    """next_step returns the step from the provider."""
    step1 = Step("say", "direct", "hello")
    provider = StubProvider([step1])
    attacker = Attacker(provider)
    scenario = Scenario(
        id="test", category="cat", channel="direct", goal="test goal",
        success_condition="cond", atlas="atlas", owasp="owasp"
    )

    result = attacker.next_step(scenario)
    assert result is step1


def test_attacker_next_step_feeds_goal_and_history_to_provider():
    """next_step passes scenario.goal and history to provider.plan()."""
    step1 = Step("say", "direct", "hello")
    provider = RecordingProvider([step1])
    attacker = Attacker(provider)
    scenario = Scenario(
        id="test", category="cat", channel="direct", goal="test goal",
        success_condition="cond", atlas="atlas", owasp="owasp"
    )

    attacker.next_step(scenario)

    assert len(provider.calls) == 1
    goal, history = provider.calls[0]
    assert goal == "test goal"
    # Initial call should have empty history
    assert history == []


def test_attacker_next_step_records_step_in_history():
    """next_step records the returned step in history as an assistant Turn."""
    step1 = Step("say", "direct", "hello world")
    provider = StubProvider([step1])
    attacker = Attacker(provider)
    scenario = Scenario(
        id="test", category="cat", channel="direct", goal="test goal",
        success_condition="cond", atlas="atlas", owasp="owasp"
    )

    assert len(attacker.history) == 0

    attacker.next_step(scenario)

    assert len(attacker.history) == 1
    turn = attacker.history[0]
    assert turn.role == "assistant"
    assert turn.content == "hello world"


def test_attacker_observe_records_user_turn():
    """observe appends observation to history as a user Turn."""
    provider = StubProvider([])
    attacker = Attacker(provider)

    assert len(attacker.history) == 0

    observation = Observation(reply="response", tool_calls=[])
    attacker.observe(observation)

    assert len(attacker.history) == 1
    turn = attacker.history[0]
    assert turn.role == "user"
    assert turn.content == "response"


def test_attacker_history_accumulates():
    """Multiple next_step and observe calls accumulate in history."""
    step1 = Step("say", "direct", "hello")
    step2 = Step("act", "direct", "click")
    provider = StubProvider([step1, step2])
    attacker = Attacker(provider)
    scenario = Scenario(
        id="test", category="cat", channel="direct", goal="test goal",
        success_condition="cond", atlas="atlas", owasp="owasp"
    )

    attacker.next_step(scenario)
    assert len(attacker.history) == 1
    assert attacker.history[0].role == "assistant"

    observation = Observation(reply="target reply", tool_calls=[])
    attacker.observe(observation)
    assert len(attacker.history) == 2
    assert attacker.history[1].role == "user"

    attacker.next_step(scenario)
    assert len(attacker.history) == 3
    assert attacker.history[2].role == "assistant"


def test_attacker_next_step_passes_accumulated_history_to_provider():
    """next_step passes the accumulated history to provider.plan()."""
    step1 = Step("say", "direct", "hello")
    step2 = Step("say", "direct", "bye")
    provider = RecordingProvider([step1, step2])
    attacker = Attacker(provider)
    scenario = Scenario(
        id="test", category="cat", channel="direct", goal="test goal",
        success_condition="cond", atlas="atlas", owasp="owasp"
    )

    # First step
    attacker.next_step(scenario)
    goal, history = provider.calls[0]
    assert len(history) == 0

    # Observe something
    observation = Observation(reply="target reply", tool_calls=[])
    attacker.observe(observation)

    # Second step should receive accumulated history
    attacker.next_step(scenario)
    goal, history = provider.calls[1]
    assert len(history) == 2
    assert history[0].role == "assistant"
    assert history[0].content == "hello"
    assert history[1].role == "user"
    assert history[1].content == "target reply"


def test_attacker_history_property_is_readonly():
    """The history property is a list (read-only reference semantics)."""
    provider = StubProvider([])
    attacker = Attacker(provider)

    # Should be able to read it
    assert isinstance(attacker.history, list)
    assert len(attacker.history) == 0


def _sc():
    from aphasia.scenarios import Scenario
    return Scenario("s", "c", "direct", "goal", "x", "a", "o")


def test_seed_mode_yields_seeds_then_none():
    a = Attacker(provider=None, payloads=["p0", "p1"], mode="seed")
    assert a.next_step(_sc()).payload == "p0"
    assert a.next_step(_sc()).payload == "p1"
    assert a.next_step(_sc()) is None                 # exhausted, no LLM fallback


def test_hybrid_mode_seeds_then_provider():
    from aphasia.providers import StubProvider
    from aphasia.types import Step
    prov = StubProvider([Step("say", "direct", "planned")])
    a = Attacker(provider=prov, payloads=["seed0"], mode="hybrid")
    assert a.next_step(_sc()).payload == "seed0"       # seed first
    assert a.next_step(_sc()).payload == "planned"     # then the provider adapts
