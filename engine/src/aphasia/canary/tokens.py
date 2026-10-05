"""Canary token generation and detection."""

import hashlib
import hmac

from aphasia.types import Canary


def mint(run_key: bytes, run_id: str, scenario_id: str, slots: list[str]) -> list[Canary]:
    """Generate HMAC-based canary tokens.

    Args:
        run_key: Secret key for HMAC.
        run_id: Unique run identifier.
        scenario_id: Scenario identifier.
        slots: List of slot names to generate tokens for.

    Returns:
        List of Canary objects with slot and token.
    """
    canaries = []
    for slot in slots:
        message = f"{run_id}:{scenario_id}:{slot}".encode()
        token_hex = hmac.new(run_key, message, hashlib.sha256).hexdigest()
        token = token_hex[:16]
        canaries.append(Canary(slot=slot, token=token))
    return canaries


def is_hit(canaries: list[Canary], text: str) -> list[Canary]:
    """Find canaries whose token appears in text.

    Args:
        canaries: List of Canary objects to search for.
        text: Text to search in.

    Returns:
        List of Canary objects found in text.
    """
    return [c for c in canaries if c.token in text]
