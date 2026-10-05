"""Append-only JSONL evidence store for recording breach-and-attack simulation steps."""

import json
from pathlib import Path


class EvidenceStore:
    """Append-only JSONL store for simulation evidence records.

    Args:
        run_dir: Path to the directory where evidence.jsonl will be stored.
                 Created if it doesn't exist.
    """

    # Required keys that must be present in each record
    REQUIRED_KEYS = {
        "run_id",
        "step_no",
        "ts",
        "target_host",
        "target_identity",
        "channel",
        "payload",
        "observation",
        "tool_calls",
        "canary_hits",
        "verdict",
        "scenario_id",
    }

    def __init__(self, run_dir: Path):
        """Initialize the evidence store.

        Args:
            run_dir: Path to the directory where evidence will be stored.
                     Created if it doesn't exist.
        """
        self.run_dir = Path(run_dir)
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.evidence_file = self.run_dir / "evidence.jsonl"

    def append(self, record: dict) -> None:
        """Append a record to the evidence store.

        Args:
            record: Dictionary containing evidence record. Must contain all required keys.

        Raises:
            ValueError: If any required key is missing from the record.
        """
        # Validate that all required keys are present
        missing_keys = self.REQUIRED_KEYS - set(record.keys())
        if missing_keys:
            raise ValueError(f"Missing required keys: {missing_keys}")

        # Append the record as a JSON line
        with open(self.evidence_file, "a", encoding="utf-8") as f:
            json.dump(record, f)
            f.write("\n")

    def read(self) -> list[dict]:
        """Read all records from the evidence store in order.

        Returns:
            List of records in the order they were appended.
            Returns empty list if the evidence file doesn't exist yet.
        """
        if not self.evidence_file.exists():
            return []

        records = []
        with open(self.evidence_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:  # Skip empty lines
                    records.append(json.loads(line))

        return records
