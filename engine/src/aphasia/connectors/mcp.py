import asyncio
import json
from urllib.parse import urlparse

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from aphasia.connectors.base import ConnectorError
from aphasia.types import Canary, Observation, Step, ToolCall

MAX_BODY = 20_000


class McpConnector:
    """Streamable-HTTP MCP target. Connects per call (lazy, stateless).

    deliver: calls `chat_tool` with {"message", "channel"}; text content -> reply.
    plant: calls `seed_tool` if the target exposes it, else a no-op (DVMCP fallback).
    """

    def __init__(self, endpoint: str, identity: str = "mcp-agent",
                 chat_tool: str = "chat", seed_tool: str = "seed_canaries",
                 timeout: float = 30.0):
        self.endpoint = endpoint
        self._identity = identity
        self.chat_tool = chat_tool
        self.seed_tool = seed_tool
        self._timeout = timeout

    @property
    def host(self) -> str:
        return urlparse(self.endpoint).hostname or ""

    @property
    def identity(self) -> str:
        return self._identity

    async def _call(self, tool: str, args: dict, only_if_listed: bool = False):
        async with streamable_http_client(self.endpoint) as (read, write, *_):
            async with ClientSession(read, write) as session:
                await session.initialize()
                if only_if_listed:
                    names = {t.name for t in (await session.list_tools()).tools}
                    if tool not in names:
                        return None
                return await session.call_tool(tool, args)

    def _run(self, tool: str, args: dict, only_if_listed: bool = False):
        """Sync only; do not call from a running event loop."""
        try:
            return asyncio.run(asyncio.wait_for(
                self._call(tool, args, only_if_listed), self._timeout))
        except Exception as e:  # SDK/transport errors vary widely
            raise ConnectorError(f"MCP call {tool} to {self.endpoint} failed: {e}") from e

    def deliver(self, step: Step) -> Observation:
        """Sync only; do not call from a running event loop."""
        result = self._run(self.chat_tool, {"message": step.payload, "channel": step.channel})
        if getattr(result, "isError", False):
            raise ConnectorError(f"MCP tool {self.chat_tool} returned an error")
        text = "".join(getattr(c, "text", "") for c in result.content)[:MAX_BODY]
        # ponytail: no structured tool_calls from raw MCP; mirror-capture does verification
        return Observation(text, [ToolCall(self.chat_tool, {"message": step.payload}, False)])

    def plant(self, canaries: list[Canary]) -> None:
        """Sync only; do not call from a running event loop."""
        if not canaries:
            return
        # Missing seeding tool (e.g. DVMCP) -> _call returns None -> no-op.
        self._run(self.seed_tool,
                  {"canaries": [{"slot": c.slot, "token": c.token} for c in canaries]},
                  only_if_listed=True)
