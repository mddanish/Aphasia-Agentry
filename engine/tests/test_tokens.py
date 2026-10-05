import pytest
from aphasia.canary.tokens import mint, is_hit
from aphasia.types import Canary


class TestMint:
    def test_determinism(self):
        """Same args should produce the same token."""
        run_key = b"test_key"
        run_id = "r1"
        scenario_id = "s1"
        slots = ["a"]

        result1 = mint(run_key, run_id, scenario_id, slots)
        result2 = mint(run_key, run_id, scenario_id, slots)

        assert result1[0].token == result2[0].token

    def test_uniqueness_by_run_id(self):
        """Different run_id should produce different token."""
        run_key = b"test_key"
        scenario_id = "s1"
        slots = ["a"]

        result1 = mint(run_key, "r1", scenario_id, slots)
        result2 = mint(run_key, "r2", scenario_id, slots)

        assert result1[0].token != result2[0].token

    def test_uniqueness_by_scenario_id(self):
        """Different scenario_id should produce different token."""
        run_key = b"test_key"
        run_id = "r1"
        slots = ["a"]

        result1 = mint(run_key, run_id, "s1", slots)
        result2 = mint(run_key, run_id, "s2", slots)

        assert result1[0].token != result2[0].token

    def test_uniqueness_by_slot(self):
        """Different slot should produce different token."""
        run_key = b"test_key"
        run_id = "r1"
        scenario_id = "s1"

        result1 = mint(run_key, run_id, scenario_id, ["a"])
        result2 = mint(run_key, run_id, scenario_id, ["b"])

        assert result1[0].token != result2[0].token

    def test_multiple_slots(self):
        """Should return one Canary per slot."""
        run_key = b"test_key"
        run_id = "r1"
        scenario_id = "s1"
        slots = ["a", "b", "c"]

        result = mint(run_key, run_id, scenario_id, slots)

        assert len(result) == 3
        assert all(isinstance(c, Canary) for c in result)
        assert [c.slot for c in result] == ["a", "b", "c"]

    def test_token_length(self):
        """Token should be 16 characters (hex digest truncated)."""
        run_key = b"test_key"
        run_id = "r1"
        scenario_id = "s1"
        slots = ["a"]

        result = mint(run_key, run_id, scenario_id, slots)

        assert len(result[0].token) == 16

    def test_token_is_hex(self):
        """Token should be hexadecimal characters."""
        run_key = b"test_key"
        run_id = "r1"
        scenario_id = "s1"
        slots = ["a"]

        result = mint(run_key, run_id, scenario_id, slots)

        # Should not raise ValueError
        int(result[0].token, 16)


class TestIsHit:
    def test_finds_planted_token(self):
        """Should find a planted token in text."""
        canaries = [Canary(slot="a", token="abcdef1234567890")]
        text = "Some text with abcdef1234567890 embedded."

        result = is_hit(canaries, text)

        assert len(result) == 1
        assert result[0].slot == "a"
        assert result[0].token == "abcdef1234567890"

    def test_returns_empty_when_not_found(self):
        """Should return empty list when token not found."""
        canaries = [Canary(slot="a", token="abcdef1234567890")]
        text = "Some text without the token."

        result = is_hit(canaries, text)

        assert result == []

    def test_finds_multiple_matches(self):
        """Should find multiple matching canaries."""
        canaries = [
            Canary(slot="a", token="aaaaaaaaaaaaaaaa"),
            Canary(slot="b", token="bbbbbbbbbbbbbbbb"),
            Canary(slot="c", token="cccccccccccccccc"),
        ]
        text = "Found aaaaaaaaaaaaaaaa and bbbbbbbbbbbbbbbb but not c."

        result = is_hit(canaries, text)

        assert len(result) == 2
        assert set(c.slot for c in result) == {"a", "b"}

    def test_substring_match_only(self):
        """Should match token as substring."""
        canaries = [Canary(slot="a", token="test")]
        text = "This is a test string."

        result = is_hit(canaries, text)

        assert len(result) == 1

    def test_partial_token_no_match(self):
        """Should not match partial tokens."""
        canaries = [Canary(slot="a", token="abcdef1234567890")]
        text = "Some text with abcdef12345 only."

        result = is_hit(canaries, text)

        assert result == []
