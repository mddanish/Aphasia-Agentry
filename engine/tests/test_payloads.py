from pathlib import Path

from aphasia.payloads import load_payloads
from aphasia.scenarios import load_yaml

OSS = Path(__file__).resolve().parents[2]


def test_every_scenario_has_seed_payloads():
    lib = load_payloads(OSS / "payloads.yaml")
    ids = [s.id for s in load_yaml(OSS / "scenarios.yaml")]
    assert set(lib) == set(ids)                       # a payload list per scenario
    assert all(lib[i] for i in ids)                   # none empty
    assert all(isinstance(p, str) and p for v in lib.values() for p in v)
