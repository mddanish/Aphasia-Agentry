import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from aphasia.evidence import EvidenceStore


class TestEvidenceStore:
    """Tests for the EvidenceStore append-only JSONL implementation."""

    def test_append_two_records_read_returns_both_in_order(self, tmp_path):
        """Append two records and verify read() returns both in order."""
        store = EvidenceStore(tmp_path)

        ts1 = datetime(2026, 10, 4, 12, 0, 0, tzinfo=timezone.utc).isoformat()
        record1 = {
            "run_id": "run-001",
            "scenario_id": "s",
            "step_no": 1,
            "ts": ts1,
            "target_host": "192.168.1.1",
            "target_identity": "user@example.com",
            "channel": "ssh",
            "payload": "ls /tmp",
            "observation": "success",
            "tool_calls": [],
            "canary_hits": [],
            "verdict": "success",
        }
        store.append(record1)

        ts2 = datetime(2026, 10, 4, 12, 0, 1, tzinfo=timezone.utc).isoformat()
        record2 = {
            "run_id": "run-001",
            "scenario_id": "s",
            "step_no": 2,
            "ts": ts2,
            "target_host": "192.168.1.1",
            "target_identity": "user@example.com",
            "channel": "ssh",
            "payload": "cat /etc/passwd",
            "observation": "access_denied",
            "tool_calls": [],
            "canary_hits": ["canary-001"],
            "verdict": "blocked",
        }
        store.append(record2)

        records = store.read()
        assert len(records) == 2
        assert records[0] == record1
        assert records[1] == record2

    def test_append_only_behavior(self, tmp_path):
        """Verify that multiple EvidenceStore instances append, not truncate."""
        store1 = EvidenceStore(tmp_path)

        ts1 = datetime(2026, 10, 4, 12, 0, 0, tzinfo=timezone.utc).isoformat()
        record1 = {
            "run_id": "run-002",
            "scenario_id": "s",
            "step_no": 1,
            "ts": ts1,
            "target_host": "10.0.0.1",
            "target_identity": "admin",
            "channel": "http",
            "payload": "GET /api/users",
            "observation": "response",
            "tool_calls": [],
            "canary_hits": [],
            "verdict": "success",
        }
        store1.append(record1)

        # Create a new store on the same directory
        store2 = EvidenceStore(tmp_path)

        ts2 = datetime(2026, 10, 4, 12, 0, 1, tzinfo=timezone.utc).isoformat()
        record2 = {
            "run_id": "run-002",
            "scenario_id": "s",
            "step_no": 2,
            "ts": ts2,
            "target_host": "10.0.0.1",
            "target_identity": "admin",
            "channel": "http",
            "payload": "POST /api/users",
            "observation": "created",
            "tool_calls": [],
            "canary_hits": [],
            "verdict": "success",
        }
        store2.append(record2)

        ts3 = datetime(2026, 10, 4, 12, 0, 2, tzinfo=timezone.utc).isoformat()
        record3 = {
            "run_id": "run-002",
            "scenario_id": "s",
            "step_no": 3,
            "ts": ts3,
            "target_host": "10.0.0.1",
            "target_identity": "admin",
            "channel": "http",
            "payload": "DELETE /api/users/1",
            "observation": "deleted",
            "tool_calls": [],
            "canary_hits": ["canary-002"],
            "verdict": "blocked",
        }
        store2.append(record3)

        # Read from store1 should now see all three records
        records = store1.read()
        assert len(records) == 3
        assert records[0] == record1
        assert records[1] == record2
        assert records[2] == record3

    def test_append_missing_required_key_raises_value_error(self, tmp_path):
        """Verify that appending a record with missing required key raises ValueError."""
        store = EvidenceStore(tmp_path)

        ts = datetime(2026, 10, 4, 12, 0, 0, tzinfo=timezone.utc).isoformat()
        record_missing_verdict = {
            "run_id": "run-003",
            "scenario_id": "s",
            "step_no": 1,
            "ts": ts,
            "target_host": "192.168.1.1",
            "target_identity": "user",
            "channel": "ssh",
            "payload": "command",
            "observation": "result",
            "tool_calls": [],
            "canary_hits": [],
            # Missing: "verdict"
        }

        with pytest.raises(ValueError):
            store.append(record_missing_verdict)

    def test_ts_roundtrip_utc_iso8601(self, tmp_path):
        """Verify that ts values in UTC ISO-8601 format round-trip correctly."""
        store = EvidenceStore(tmp_path)

        ts = datetime(2026, 10, 4, 14, 30, 45, 123456, tzinfo=timezone.utc).isoformat()
        record = {
            "run_id": "run-004",
            "scenario_id": "s",
            "step_no": 1,
            "ts": ts,
            "target_host": "example.com",
            "target_identity": "test",
            "channel": "api",
            "payload": "test",
            "observation": "ok",
            "tool_calls": [],
            "canary_hits": [],
            "verdict": "success",
        }
        store.append(record)

        records = store.read()
        assert len(records) == 1
        assert records[0]["ts"] == ts
