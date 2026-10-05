"""Exposure score 0..100.

score = round(100 * sum(0.7 + 0.3/steps for each proven scenario) / total_scenarios)
A proven finding (canary-backed "success" or metered cost breach) in 1 step counts fully;
slower ones count down to 0.7. No proven findings -> 0.
"""

PROVEN = ("success", "metered")


def exposure_score(run_result) -> int:
    rs = run_result.results
    if not rs:
        return 0
    pts = sum(0.7 + 0.3 / max(r.steps, 1) for r in rs if r.verdict in PROVEN)
    return round(100 * pts / len(rs))
