"""Model-key matching and cost computation."""

from __future__ import annotations

import pytest

from claude_cloak import pricing


@pytest.mark.parametrize(
    ("model", "key"),
    [
        ("claude-opus-4-5-20251101", "opus-4.5"),
        ("claude-opus-4-1-20250805", "opus-4.1"),
        ("claude-opus-4-20250514", "opus-4"),
        ("claude-sonnet-4-20250514", "sonnet-4"),
        ("claude-sonnet-5", "sonnet-5"),
        ("claude-fable-5-1", "fable-5.1"),
        ("claude-fable-5", "fable-5"),
        ("claude-mythos-5-1", "mythos-5.1"),
        ("claude-3-5-haiku-20241022", "haiku-3.5"),
        ("", "unknown"),
        (None, "unknown"),
    ],
)
def test_normalize_model_key(model, key):
    assert pricing._normalize_model_key(model) == key


def test_opus_45_and_newer_are_not_billed_at_the_legacy_opus_rate():
    """Opus 4.5+ is $5/$25; only Opus 4.0/4.1 and Opus 3 carry $15/$75."""
    assert pricing.PRICING["opus-4.5"]["input"] == 5.0
    assert pricing.PRICING["opus-4.5"]["output"] == 25.0
    assert pricing.PRICING["opus-4.1"]["input"] == 15.0
    assert pricing.PRICING["opus-4"]["output"] == 75.0
    assert pricing.PRICING["opus-3"]["input"] == 15.0


# Fable 5.1 / Mythos 5.1 read at 0.025x the input price instead of the usual
# 0.1x; every other row follows the standard multiplier.
DISCOUNTED_CACHE_READ = {"fable-5.1": 0.025, "mythos-5.1": 0.025}


def test_cache_tiers_follow_the_standard_multipliers():
    """5m write = 1.25x input, 1h write = 2x, read = 0.1x (0.025x on 5.1).

    Published list prices are rounded to the cent (haiku-3's 5m write is $0.30,
    not $0.3125, and its read tier is $0.03 not $0.025), so the check allows a
    one-cent absolute tolerance on top of a small relative one.
    """
    for key, row in pricing.PRICING.items():
        read_multiplier = DISCOUNTED_CACHE_READ.get(key, 0.1)
        assert row["cache_write_5m"] == pytest.approx(row["input"] * 1.25, rel=0.05, abs=0.005), key
        assert row["cache_write_1h"] == pytest.approx(row["input"] * 2.0, rel=0.05, abs=0.005), key
        assert row["cache_read"] == pytest.approx(
            row["input"] * read_multiplier, rel=0.05, abs=0.005
        ), key


def test_sonnet_5_is_billed_at_its_two_ten_rate():
    """Sonnet 5 is $2/$10, not the $3/$15 of the Sonnet 4.x line."""
    assert pricing.PRICING["sonnet-5"]["input"] == 2.0
    assert pricing.PRICING["sonnet-5"]["output"] == 10.0


def test_fable_51_cache_reads_are_a_quarter_of_the_fable_5_rate():
    assert pricing.PRICING["fable-5.1"]["cache_read"] == 0.25
    assert pricing.PRICING["fable-5"]["cache_read"] == 1.00


def test_compute_cost_sums_every_tier():
    usage = {
        "input_tokens": 1_000_000,
        "output_tokens": 1_000_000,
        "cache_read_input_tokens": 1_000_000,
    }
    row = pricing.PRICING["sonnet-5"]
    expected = row["input"] + row["output"] + row["cache_read"]
    assert pricing._compute_cost("sonnet-5", usage) == pytest.approx(expected, rel=1e-6)


def test_unknown_model_uses_the_fallback_rate_not_zero():
    cost = pricing._compute_cost("unknown", {"input_tokens": 1_000_000})
    assert cost == pytest.approx(pricing.PRICING_FALLBACK["input"])
    assert cost > 0
