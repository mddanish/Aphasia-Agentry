"""Live end-to-end run against the running fixture via litellm. Skipped unless OLLAMA_HOST is set.

Uses an Ollama backend through litellm (model ollama/<name>, api_base=OLLAMA_HOST). Any
litellm model works; this test defaults to Ollama because it needs no API key.
"""
import os

import pytest

from aphasia.cli import main

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(not os.environ.get("OLLAMA_HOST"), reason="OLLAMA_HOST not set"),
]


def test_live_run_against_fixture(tmp_path):
    # Set OLLAMA_MODEL to a model your server serves and that is strong enough to trigger the fixture.
    model = os.environ.get("OLLAMA_MODEL", "llama3.2:1b")
    rc = main(["run", "--target", "fixture", "--mode", "adaptive",
               "--model", f"ollama/{model}", "--api-base", os.environ["OLLAMA_HOST"],
               "--out", str(tmp_path)])
    assert rc == 1  # 1 == at least one scenario succeeded (2 would be a target/provider error)
    assert (tmp_path / "report.html").exists()
