import json
from urllib.parse import urlparse

import httpx

from aphasia.connectors.base import ConnectorError
from aphasia.types import Canary, Observation, Step, ToolCall

MAX_BODY = 20_000


class HttpConnector:
    def __init__(self, base_url: str, plant_url: str | None = None,
                 identity: str = "http-agent", timeout: float = 30.0):
        self.base_url = base_url
        self.plant_url = plant_url
        self._identity = identity
        self._timeout = timeout

    @property
    def host(self) -> str:
        return urlparse(self.base_url).hostname or ""

    @property
    def identity(self) -> str:
        return self._identity

    def _post(self, url: str, body: dict) -> str:
        try:
            r = httpx.post(url, json=body, timeout=self._timeout)
        except httpx.HTTPError as e:
            raise ConnectorError(f"cannot reach {url}: {e}") from e
        if r.status_code != 200:
            raise ConnectorError(f"{url} returned HTTP {r.status_code}")
        return r.text[:MAX_BODY]

    def deliver(self, step: Step) -> Observation:
        text = self._post(self.base_url, {"message": step.payload, "channel": step.channel})
        try:
            data = json.loads(text)
            calls = [
                ToolCall(str(c["name"]), dict(c.get("args") or {}), bool(c.get("mutating", False)))
                for c in data.get("tool_calls") or []
            ]
            return Observation(str(data.get("reply", "")), calls)
        except (ValueError, AttributeError, KeyError, TypeError) as e:
            raise ConnectorError(f"malformed reply from {self.base_url}: {e}") from e

    def plant(self, canaries: list[Canary]) -> None:
        if self.plant_url:
            self._post(self.plant_url,
                       {"canaries": [{"slot": c.slot, "token": c.token} for c in canaries]})
