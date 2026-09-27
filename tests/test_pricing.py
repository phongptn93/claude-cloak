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
        ("claude-opus-5-5", "opus-5.5"),
        ("claude-opus-5", "opus-5"),
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


# Fable 5.1 / Mythos 5.1 read at 0.025x the input price and Opus 5.5 at 0.05x
# instead of the usual 0.1x; every other row follows the standard multiplier.
DISCOUNTED_CACHE_READ = {"fable-5.1": 0.025, "mythos-5.1": 0.025, "opus-5.5": 0.05}


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


# Every model id Anthropic currently serves, as it appears in the response
# `model` field. A new id belongs here the day it ships: if it resolves to
# "unknown" it is being costed at the fallback rate, and if it resolves to an
# older sibling (claude-opus-5-5 -> opus-5) it is silently mispriced.
SERVED_MODEL_IDS = {
    "claude-fable-5-1": "fable-5.1",
    "claude-mythos-5-1": "mythos-5.1",
    "claude-fable-5": "fable-5",
    "claude-mythos-5": "mythos-5",
    "claude-opus-5-5": "opus-5.5",
    "claude-opus-5": "opus-5",
    "claude-sonnet-5": "sonnet-5",
    "claude-opus-4-8": "opus-4.8",
    "claude-opus-4-7": "opus-4.7",
    "claude-opus-4-6": "opus-4.6",
    "claude-opus-4-5-20251101": "opus-4.5",
    "claude-opus-4-1-20250805": "opus-4.1",
    "claude-sonnet-4-6": "sonnet-4.6",
    "claude-sonnet-4-5-20250929": "sonnet-4",
    "claude-haiku-4-5": "haiku-4",
    "claude-haiku-4-5-20251001": "haiku-4",
}


@pytest.mark.parametrize(("model", "key"), sorted(SERVED_MODEL_IDS.items()))
def test_every_served_model_has_a_price(model, key):
    assert pricing._normalize_model_key(model) == key
    assert key in pricing.PRICING


def test_opus_55_is_not_billed_at_the_opus_5_rate():
    """claude-opus-5-5 contains "opus-5"; the longer key must win."""
    assert pricing.PRICING["opus-5.5"]["input"] == 4.0
    assert pricing.PRICING["opus-5.5"]["output"] == 20.0
    assert pricing.PRICING["opus-5.5"]["cache_read"] == 0.20


def test_bundled_pricing_file_is_valid_and_complete():
    table, doc = pricing._load_bundled()
    assert doc["schema"] == 1
    for key, rates in table.items():
        assert rates, key
        assert all(set(pricing.TIERS) <= set(r) for r in rates), key


def _doc(models):
    return {"schema": 1, "models": models}


RATE = {"input": 1, "output": 5, "cache_write_5m": 1.25, "cache_write_1h": 2, "cache_read": 0.1}


def test_the_rate_in_force_follows_effective_from():
    table = pricing.parse_pricing(
        _doc({"opus-9": [{**RATE, "effective_from": "2027-01-01", "input": 2}, RATE]})
    )
    assert pricing.rates_on(table, "opus-9", "2026-12-31")["input"] == 1
    assert pricing.rates_on(table, "opus-9", "2027-01-01")["input"] == 2
    assert pricing.rates_on(table, "missing", "2027-01-01") is None


def test_a_model_priced_only_from_a_future_date_has_no_rate_yet():
    table = pricing.parse_pricing(_doc({"opus-9": [{**RATE, "effective_from": "2099-01-01"}]}))
    assert pricing.rates_on(table, "opus-9", "2026-09-27") is None


@pytest.mark.parametrize(
    "doc",
    [
        {"schema": 2, "models": {"opus-9": [RATE]}},
        _doc({}),
        _doc({"Opus 9": [RATE]}),
        _doc({"opus-9": []}),
        _doc({"opus-9": [{**RATE, "input": -1}]}),
        _doc({"opus-9": [{**RATE, "output": "5"}]}),
        _doc({"opus-9": [{k: v for k, v in RATE.items() if k != "cache_read"}]}),
        _doc({"opus-9": [{**RATE, "effective_from": "01/01/2027"}]}),
        _doc({"opus-9": [RATE, RATE]}),
    ],
)
def test_a_malformed_pricing_document_is_rejected_whole(doc):
    with pytest.raises(pricing.PricingError):
        pricing.parse_pricing(doc)


async def test_remote_refresh_merges_over_the_bundled_table(monkeypatch, tmp_path):
    import httpx

    doc = _doc({"opus-9": [RATE], "sonnet-5": [{**RATE, "input": 7}]})
    transport = httpx.MockTransport(lambda req: httpx.Response(200, json=doc))
    monkeypatch.setattr(pricing, "PRICING_REMOTE_URL", "https://example.test/pricing.json")
    monkeypatch.setenv("PRICING_REMOTE_CACHE_PATH", str(tmp_path / "remote.json"))
    try:
        async with httpx.AsyncClient(transport=transport) as client:
            assert await pricing.refresh_remote_pricing(client) is True
        assert pricing.PRICING["opus-9"]["input"] == 1
        assert pricing.PRICING["sonnet-5"]["input"] == 7
        assert pricing.PRICING["opus-5.5"]["input"] == 4  # bundled rows survive
        assert pricing.PRICING_SOURCE["origin"] == "remote"
        assert (tmp_path / "remote.json").exists()
    finally:
        pricing.install_table({}, "bundled")


async def test_a_bad_remote_document_keeps_the_current_table(monkeypatch):
    import httpx

    transport = httpx.MockTransport(lambda req: httpx.Response(200, json={"schema": 1}))
    monkeypatch.setattr(pricing, "PRICING_REMOTE_URL", "https://example.test/pricing.json")
    before = dict(pricing.PRICING)
    async with httpx.AsyncClient(transport=transport) as client:
        assert await pricing.refresh_remote_pricing(client) is False
    assert before == pricing.PRICING
    assert "PricingError" in pricing.PRICING_SOURCE["last_error"]
    pricing.PRICING_SOURCE["last_error"] = None
