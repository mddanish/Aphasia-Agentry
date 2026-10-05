from aphasia.types import Step, Turn

from .base import ProviderError


class StubProvider:
    """Yields scripted steps in order; raises ProviderError when exhausted."""

    def __init__(self, steps: list[Step]):
        self._steps = list(steps)
        self._i = 0

    def plan(self, goal: str, history: list[Turn]) -> Step:
        if self._i >= len(self._steps):
            raise ProviderError("StubProvider script exhausted")
        step = self._steps[self._i]
        self._i += 1
        return step
