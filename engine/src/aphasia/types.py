from dataclasses import dataclass
from typing import Literal


@dataclass
class Turn:
    role: str
    content: str


@dataclass
class Step:
    kind: str
    channel: str
    payload: str


@dataclass
class ToolCall:
    name: str
    args: dict
    mutating: bool


@dataclass
class Observation:
    reply: str
    tool_calls: list[ToolCall]


@dataclass
class Canary:
    slot: str
    token: str


Verdict = Literal["success", "metered", "mirror_only", "clean", "capped", "error"]
