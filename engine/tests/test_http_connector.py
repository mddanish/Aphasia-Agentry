import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from aphasia.connectors import ConnectorError, HttpConnector
from aphasia.types import Canary, Step

state = {"body": b"", "status": 200, "seen": []}


class H(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers["Content-Length"])
        state["seen"].append((self.path, json.loads(self.rfile.read(n))))
        self.send_response(state["status"])
        self.end_headers()
        self.wfile.write(state["body"])

    def log_message(self, *a):
        pass


@pytest.fixture
def server():
    state.update(body=b"", status=200, seen=[])
    s = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{s.server_port}"
    s.shutdown()


STEP = Step("user_message", "chat", "hi")


def test_deliver_maps_reply(server):
    state["body"] = json.dumps({"reply": "ok", "tool_calls": [
        {"name": "send_email", "args": {"to": "a"}, "mutating": True}]}).encode()
    c = HttpConnector(server + "/chat")
    obs = c.deliver(STEP)
    assert obs.reply == "ok"
    assert (obs.tool_calls[0].name, obs.tool_calls[0].args, obs.tool_calls[0].mutating) == (
        "send_email", {"to": "a"}, True)
    assert state["seen"][0] == ("/chat", {"message": "hi", "channel": "chat"})
    assert c.host == "127.0.0.1"


def test_unreachable():
    with pytest.raises(ConnectorError):
        HttpConnector("http://127.0.0.1:1/chat").deliver(STEP)


def test_non_200(server):
    state["status"] = 500
    with pytest.raises(ConnectorError):
        HttpConnector(server).deliver(STEP)


def test_oversized_truncated(server):
    state["body"] = json.dumps({"reply": "x" * 50_000, "tool_calls": []}).encode()
    with pytest.raises(ConnectorError):  # truncation cuts the JSON -> malformed
        HttpConnector(server).deliver(STEP)
    c = HttpConnector(server)
    assert len(c._post(server, {})) == 20_000


def test_plant(server):
    HttpConnector(server, plant_url=server + "/seed").plant([Canary("s", "t")])
    assert state["seen"] == [("/seed", {"canaries": [{"slot": "s", "token": "t"}]})]
    HttpConnector(server).plant([Canary("s", "t")])
    assert len(state["seen"]) == 1
