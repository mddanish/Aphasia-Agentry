"""Attacker agent for Agentic BAS.

The Attacker owns a single internal history of turns (deliveries and observations).
The run loop (Task 10) owns step/token caps and the kill switch.

Important: The goal is passed separately to plan() via the provider. History
should contain only the running turns (deliveries as "assistant", observations
as "user"), not a duplicate of the goal. This is critical for providers like
OllamaProvider that append the goal as a final user message on every call.
"""

from aphasia.providers import Provider
from aphasia.scenarios import Scenario
from aphasia.types import Observation, Step, Turn


class Attacker:
    """Attack orchestrator driven by a planning provider.

    Owns a single internal history of turns. Each next_step records the delivered
    step to history; each observe records the target reply to history.
    """

    def __init__(self, provider: Provider | None = None,
                 payloads: list[str] | None = None, mode: str = "hybrid"):
        """Initialize attacker.

        Args:
            provider: A Provider implementing plan(goal, history) -> Step. May be
                None in "seed" mode (no LLM needed).
            payloads: Seed injection strings to try before/instead of planning.
            mode: "seed" (only seeds), "adaptive" (only the provider), or "hybrid"
                (seeds first, then the provider adapts). Default "hybrid".
        """
        self.provider = provider
        self._seeds = list(payloads or [])
        self._mode = mode
        self._i = 0
        self._history: list[Turn] = []

    @property
    def history(self) -> list[Turn]:
        """Read-only view of the attacker's running history."""
        return self._history

    def next_step(self, scenario: Scenario) -> Step | None:
        """Return the next attack step and record it to history.

        In "seed"/"hybrid" mode, the next unused seed payload is returned first. Once
        seeds are exhausted: "hybrid"/"adaptive" plan via the provider; "seed" returns
        None (no more attempts — the run loop ends the scenario).
        """
        if self._mode in ("seed", "hybrid") and self._i < len(self._seeds):
            step = Step(kind="say", channel=scenario.channel, payload=self._seeds[self._i])
            self._i += 1
        elif self._mode == "seed" or self.provider is None:
            return None
        else:
            step = self.provider.plan(scenario.goal, self._history)
        self._history.append(Turn(role="assistant", content=step.payload))
        return step

    def observe(self, observation: Observation) -> None:
        """Record a target observation in the attacker's running history.

        Appends a Turn with role="user" and content=observation.reply.

        Args:
            observation: An Observation from the target system, containing a reply
                        and tool_calls.
        """
        # Append the observation as a Turn with role "user"
        turn = Turn(role="user", content=observation.reply)
        self._history.append(turn)
