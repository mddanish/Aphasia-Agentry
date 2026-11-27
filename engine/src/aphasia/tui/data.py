"""View model for the TUI. One RunView per run directory (or the bundled demo)."""
import json
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path


@dataclass
class RunView:
    run_id: str
    started: str
    target: str
    mode: str
    duration_min: int
    siem: str
    scenarios: list[dict]
    steps: list[dict]
    gaps: list[dict]
    deploy_mode: str = "direct"          # direct = black box, proxy = LLM gateway in the path
    exchanges: list[dict] = field(default_factory=list)

    def steps_for(self, scenario_id: str) -> list[dict]:
        return [s for s in self.steps if s["scenario"] == scenario_id]

    def count(self, key: str, value) -> int:
        return sum(1 for s in self.steps if s.get(key) == value)


def load_demo() -> RunView:
    raw = resources.files("aphasia.tui").joinpath("demo_run.json").read_text()
    return RunView(**json.loads(raw))


def load_run(run_dir: Path) -> RunView:
    """Load a real run. Expects run_view.json written by the run + Wazuh correlation step."""
    return RunView(**json.loads((Path(run_dir) / "run_view.json").read_text()))
