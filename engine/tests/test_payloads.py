from aphasia.payloads import DEFAULT_PATH as PAYLOADS, load_payloads
from aphasia.scenarios import DEFAULT_PATH as SCENARIOS, load_yaml


def test_every_scenario_has_seed_payloads():
    lib = load_payloads(PAYLOADS)
    ids = [s.id for s in load_yaml(SCENARIOS)]
    assert set(lib) == set(ids)                       # a payload list per scenario
    assert all(lib[i] for i in ids)                   # none empty
    assert all(isinstance(p, str) and p for v in lib.values() for p in v)
