"""Seed payload library: curated known-bad injection strings keyed by scenario id.

Feeds the attacker in `seed` and `hybrid` modes so a run reproduces coverage without
an LLM. The LLM (adaptive/hybrid) still handles novel attacks on top of these.
"""
import yaml


def load_payloads(path) -> dict[str, list[str]]:
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return {str(k): [str(p) for p in (v or [])] for k, v in (data.get("payloads") or {}).items()}
