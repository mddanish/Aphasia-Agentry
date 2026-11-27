"""Technique catalog: merged, deduplicated taxonomy (AATMF + Arcanum + ZeroLeaks), and scan selection.

The catalog is reference metadata — it says what exists, which Aphasia scenario tests it, and whether
proxy mode sees more. Execution still runs the existing scenarios; `select()` maps a scan choice to the
scenario ids to run. A technique with testable == "none" is never runnable (training/supply-chain/infra).
"""
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources

import yaml


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    category: str
    tactic: str
    owasp: str
    atlas: str
    scenario: str          # existing Aphasia scenario that exercises it, or "" if uncovered
    channel: str
    testable: str          # both | direct | proxy | none
    proxy_better: bool
    sources: dict          # {aatmf, arcanum, zeroleaks}

    @property
    def runnable(self) -> bool:
        return self.testable != "none"

    def runnable_in(self, mode: str) -> bool:
        """Can this technique run in the chosen deploy mode? proxy-only ones need proxy mode."""
        if not self.runnable or not self.scenario:
            return False
        return mode == "proxy" or self.testable in ("both", "direct")


@dataclass(frozen=True)
class Category:
    id: str
    name: str
    proxy_hint: str        # strong | partial | direct | none


@dataclass(frozen=True)
class Catalog:
    categories: tuple[Category, ...]
    techniques: tuple[Technique, ...]

    def category(self, cid: str) -> Category | None:
        return next((c for c in self.categories if c.id == cid), None)

    def in_category(self, cid: str) -> list[Technique]:
        return [t for t in self.techniques if t.category == cid]

    def scenarios_for(self, cid: str) -> list[str]:
        """Scenario ids covered by a category (deduped, order-stable)."""
        out = []
        for t in self.in_category(cid):
            if t.scenario and t.scenario not in out:
                out.append(t.scenario)
        return out


@lru_cache(maxsize=1)
def load() -> Catalog:
    raw = yaml.safe_load(resources.files("aphasia.data").joinpath("catalog.yaml").read_text())
    cats = tuple(Category(**c) for c in raw["categories"])
    techs = tuple(Technique(**t) for t in raw["techniques"])
    return Catalog(cats, techs)


def category_ids() -> list[str]:
    return [c.id for c in load().categories if c.id != "context"]


def select(choice: str, available: list[str]) -> tuple[list[str], list[str]]:
    """Map a scan choice to scenario ids to run, filtered to the ones actually registered.

    choice: "all" | "<category-id>" | "<scenario-id>".
    Returns (scenarios_to_run, notes). Never raises on an empty result; the caller decides.
    """
    cat = load()
    avail = set(available)
    if choice == "all":
        picked = [s for s in available]
        return picked, []
    if cat.category(choice):
        want = cat.scenarios_for(choice)
        picked = [s for s in want if s in avail]
        missing = [s for s in want if s not in avail]
        notes = [f"category {choice}: {len(picked)} runnable scenario(s)"]
        if missing:
            notes.append(f"not yet implemented: {', '.join(missing)}")
        if not want:
            notes.append(f"category {choice} has no runnable scenarios yet (reference only)")
        return picked, notes
    if choice in avail:
        return [choice], []
    return [], [f"unknown scan choice '{choice}': use all, a category "
                f"({', '.join(category_ids())}), or a scenario id"]
