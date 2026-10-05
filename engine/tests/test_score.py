from pathlib import Path
from aphasia.run import RunResult, ScenarioResult
from aphasia.score import exposure_score


def rr(*vs):
    return RunResult("r", Path("."), [ScenarioResult(f"s{i}", v, [], 2) for i, v in enumerate(vs)])


def test_score():
    assert exposure_score(rr("success", "clean", "clean", "capped", "error")) > 0
    assert exposure_score(rr("clean", "capped", "mirror_only")) == 0
    assert exposure_score(rr("success", "success", "clean")) > exposure_score(rr("success", "clean", "clean"))
    assert exposure_score(rr()) == 0
