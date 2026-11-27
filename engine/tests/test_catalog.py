import pytest

from aphasia import catalog


def test_catalog_loads_unique_and_valid():
    cat = catalog.load()
    ids = [t.id for t in cat.techniques]
    assert len(ids) == len(set(ids)), "technique ids must be unique"
    cat_ids = {c.id for c in cat.categories}
    assert all(t.category in cat_ids for t in cat.techniques), "every technique in a known category"
    assert len(cat.techniques) >= 55


def test_source_ids_map_one_to_one():
    """A taxonomy source id (e.g. an AATMF technique) maps to at most one Aphasia technique."""
    from collections import defaultdict
    seen = defaultdict(list)
    for t in catalog.load().techniques:
        for src, val in t.sources.items():
            if val:
                seen[(src, val)].append(t.id)
    dups = {k: v for k, v in seen.items() if len(v) > 1}
    assert not dups, f"source id reused across techniques: {dups}"


def test_every_runnable_points_at_a_real_scenario():
    from aphasia.scenarios import DEFAULT_PATH, load_yaml
    known = {s.id for s in load_yaml(DEFAULT_PATH)}
    for t in catalog.load().techniques:
        if t.scenario:
            assert t.scenario in known, f"{t.id} -> unknown scenario {t.scenario}"
        if t.testable == "none":
            assert not t.scenario, f"{t.id} is reference-only but names a scenario"


def test_select_all_category_scenario_and_unknown():
    avail = ["direct_injection", "tool_misuse", "mcp_tool_poisoning", "data_exfil"]
    assert catalog.select("all", avail) == (avail, [])
    picked, notes = catalog.select("tool_mcp", avail)
    assert picked == ["tool_misuse", "mcp_tool_poisoning"] and notes
    assert catalog.select("data_exfil", avail)[0] == ["data_exfil"]
    picked, notes = catalog.select("bogus", avail)
    assert picked == [] and "unknown scan choice" in notes[0]


def test_context_category_is_reference_only():
    picked, notes = catalog.select("context", ["direct_injection"])
    assert picked == [] and any("reference only" in n for n in notes)
    assert "context" not in catalog.category_ids()


def test_proxy_only_technique_needs_proxy_mode():
    spoof = next(t for t in catalog.load().techniques if t.id == "AP-T29")  # tool-call spoofing, proxy
    assert spoof.testable == "proxy" and not spoof.runnable_in("direct")
    override = next(t for t in catalog.load().techniques if t.id == "AP-T01")
    assert override.runnable_in("direct") and override.runnable_in("proxy")
