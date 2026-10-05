"""Record-only, fail-closed tool mirror. real_tool runs ONLY for read-only calls."""
from dataclasses import dataclass
from typing import Literal

from aphasia.types import ToolCall


@dataclass
class MirrorPolicy:
    mutating_names: set[str]


@dataclass
class MirrorResult:
    executed: bool
    captured: ToolCall | None
    blocked: bool


def classify(call: ToolCall, policy: MirrorPolicy) -> Literal["pass", "mirror", "block"]:
    # Mutating if flagged OR named by policy (either signal alone is enough).
    if call.mutating is True or call.name in policy.mutating_names:
        return "mirror"
    # Read-only only when explicitly False; anything else (None, non-bool) is unknown.
    if call.mutating is False:
        return "pass"
    return "block"


class Mirror:
    def __init__(self, policy: MirrorPolicy):
        self.policy = policy

    def route(self, call: ToolCall, real_tool) -> MirrorResult:
        kind = classify(call, self.policy)
        if kind == "pass":
            real_tool(call)
            return MirrorResult(executed=True, captured=None, blocked=False)
        if kind == "mirror":
            return MirrorResult(executed=False, captured=call, blocked=False)
        return MirrorResult(executed=False, captured=None, blocked=True)
