"""End-to-end proof: seed mode cracks the bundled fixture with NO LLM, in-process (no docker).
Serves the real Flask fixture on an ephemeral port and runs the engine against it."""
import threading
from pathlib import Path

import pytest
from werkzeug.serving import make_server

from aphasia.connectors import HttpConnector
from aphasia.payloads import load_payloads
from aphasia.run import run_all
from aphasia.scenarios import load_yaml

OSS = Path(__file__).resolve().parents[2]


@pytest.fixture
def base_url():
    import sys
    sys.path.insert(0, str(OSS / "fixture" / "agent"))
    import app as agent_app
    srv = make_server("127.0.0.1", 0, agent_app.app)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def test_seed_mode_cracks_fixture(base_url, tmp_path):
    from aphasia.scenarios import DEFAULT_PATH as SCENARIOS
    from aphasia.payloads import DEFAULT_PATH as PAYLOADS
    scs = load_yaml(SCENARIOS)
    payloads = load_payloads(PAYLOADS)
    conn = HttpConnector(base_url + "/chat", plant_url=base_url + "/seed")
    res = run_all(scs, conn, provider=None, run_dir=tmp_path, mode="seed", payloads=payloads)
    proven = [r for r in res.results if r.verdict in ("success", "metered")]
    # All 11 OWASP categories should be provable by the curated seeds, deterministically.
    assert len(proven) == len(scs), [(r.scenario_id, r.verdict) for r in res.results]
