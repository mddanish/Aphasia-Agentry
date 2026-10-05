from aphasia.connectors import McpConnector


def test_plant_empty_is_noop_without_server():
    c = McpConnector("http://127.0.0.1:1/mcp")  # nothing listening
    c.plant([])
    assert c.host == "127.0.0.1"


def _stub_sdk(monkeypatch, tool_names):
    from contextlib import asynccontextmanager
    from types import SimpleNamespace

    from aphasia.connectors import mcp as m

    calls = []

    class FakeSession:
        def __init__(self, *a):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def initialize(self):
            pass

        async def list_tools(self):
            return SimpleNamespace(tools=[SimpleNamespace(name=n) for n in tool_names])

        async def call_tool(self, name, args):
            calls.append(name)
            return SimpleNamespace(isError=False, content=[])

    @asynccontextmanager
    async def fake_transport(url):
        yield (None, None)

    monkeypatch.setattr(m, "ClientSession", FakeSession)
    monkeypatch.setattr(m, "streamable_http_client", fake_transport)
    return calls


def test_plant_noop_when_target_has_no_seed_tool(monkeypatch):
    from aphasia.types import Canary

    calls = _stub_sdk(monkeypatch, ["add", "read_file"])  # DVMCP-like
    McpConnector("http://x/mcp").plant([Canary("a", "tok")])
    assert calls == []


def test_plant_calls_seed_tool_when_exposed(monkeypatch):
    from aphasia.types import Canary

    calls = _stub_sdk(monkeypatch, ["seed_canaries"])
    McpConnector("http://x/mcp").plant([Canary("a", "tok")])
    assert calls == ["seed_canaries"]
