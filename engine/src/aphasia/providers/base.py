from typing import Protocol

from aphasia.types import Step, Turn


class ProviderError(Exception):
    """Provider failed (unreachable, bad status, malformed reply, exhausted script)."""


class Provider(Protocol):
    def plan(self, goal: str, history: list[Turn]) -> Step: ...
