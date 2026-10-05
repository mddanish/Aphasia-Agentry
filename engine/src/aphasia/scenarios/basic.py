from dataclasses import dataclass
from importlib.resources import files

import yaml


@dataclass
class Scenario:
    id: str
    category: str
    channel: str
    goal: str
    success_condition: str
    atlas: str
    owasp: str


REGISTRY: dict[str, Scenario] = {}


def register(scenario: Scenario) -> None:
    REGISTRY[scenario.id] = scenario


def load_yaml(path) -> list[Scenario]:
    with open(path, encoding="utf-8") as f:
        items = yaml.safe_load(f)["scenarios"]
    scenarios = [Scenario(**item) for item in items]
    for s in scenarios:
        register(s)
    return scenarios


DEFAULT_PATH = files("aphasia").joinpath("data/scenarios.yaml")


def load_default():
    """Load the scenarios shipped with the package."""
    return load_yaml(DEFAULT_PATH)
