from typing import Protocol

from aphasia.types import Canary, Observation, Step


class ConnectorError(Exception):
    """Target unreachable, non-200, or malformed reply."""


class TargetConnector(Protocol):
    @property
    def host(self) -> str: ...

    @property
    def identity(self) -> str: ...

    def deliver(self, step: Step) -> Observation: ...

    def plant(self, canaries: list[Canary]) -> None: ...
