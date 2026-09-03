"""Model price table and cost computation."""

from __future__ import annotations

import contextlib
import os

# Per-million-token USD prices. Defaults are public Anthropic list prices
# at the time of writing — override via PRICING_<KEY>_<TIER>=<usd> env if
# Anthropic changes them or you want plan-specific rates.
#
# Tiers: input, output, cache_write_5m, cache_write_1h, cache_read.
# Cache tiers follow Anthropic's standard multipliers on the input price:
#   5m write = 1.25x, 1h write = 2x, read = 0.1x.
# Model key is matched by substring against the response `model` field;
# longer keys win, so `opus-4.8` is picked over the legacy `opus-4` entry.
#
# IMPORTANT: Opus 4.5 and newer are $5/$25 — only Opus 4.0/4.1 and Opus 3
# carry the old $15/$75 rate. Keep those rows separate or 4.x traffic gets
# billed at 3x its real cost.
PRICING_DEFAULTS: dict[str, dict[str, float]] = {
    # ---- Claude 5 family ----
    "fable-5": {
        "input": 10.00,
        "output": 50.00,
        "cache_write_5m": 12.50,
        "cache_write_1h": 20.00,
        "cache_read": 1.00,
    },
    "mythos-5": {
        "input": 10.00,
        "output": 50.00,
        "cache_write_5m": 12.50,
        "cache_write_1h": 20.00,
        "cache_read": 1.00,
    },
    "opus-5": {
        "input": 5.00,
        "output": 25.00,
        "cache_write_5m": 6.25,
        "cache_write_1h": 10.00,
        "cache_read": 0.50,
    },
    "sonnet-5": {
        "input": 3.00,
        "output": 15.00,
        "cache_write_5m": 3.75,
        "cache_write_1h": 6.00,
        "cache_read": 0.30,
    },
    # ---- Opus 4.x (4.5+ moved to the $5/$25 tier) ----
    "opus-4.8": {
        "input": 5.00,
        "output": 25.00,
        "cache_write_5m": 6.25,
        "cache_write_1h": 10.00,
        "cache_read": 0.50,
    },
    "opus-4.7": {
        "input": 5.00,
        "output": 25.00,
        "cache_write_5m": 6.25,
        "cache_write_1h": 10.00,
        "cache_read": 0.50,
    },
    "opus-4.6": {
        "input": 5.00,
        "output": 25.00,
        "cache_write_5m": 6.25,
        "cache_write_1h": 10.00,
        "cache_read": 0.50,
    },
    "opus-4.5": {
        "input": 5.00,
        "output": 25.00,
        "cache_write_5m": 6.25,
        "cache_write_1h": 10.00,
        "cache_read": 0.50,
    },
    "opus-4.1": {
        "input": 15.00,
        "output": 75.00,
        "cache_write_5m": 18.75,
        "cache_write_1h": 30.00,
        "cache_read": 1.50,
    },
    "opus-4": {
        "input": 15.00,
        "output": 75.00,
        "cache_write_5m": 18.75,
        "cache_write_1h": 30.00,
        "cache_read": 1.50,
    },
    # ---- Sonnet / Haiku ----
    "sonnet-4.6": {
        "input": 3.00,
        "output": 15.00,
        "cache_write_5m": 3.75,
        "cache_write_1h": 6.00,
        "cache_read": 0.30,
    },
    "sonnet-4": {
        "input": 3.00,
        "output": 15.00,
        "cache_write_5m": 3.75,
        "cache_write_1h": 6.00,
        "cache_read": 0.30,
    },
    "haiku-4": {
        "input": 1.00,
        "output": 5.00,
        "cache_write_5m": 1.25,
        "cache_write_1h": 2.00,
        "cache_read": 0.10,
    },
    "opus-3": {
        "input": 15.00,
        "output": 75.00,
        "cache_write_5m": 18.75,
        "cache_write_1h": 30.00,
        "cache_read": 1.50,
    },
    "sonnet-3.7": {
        "input": 3.00,
        "output": 15.00,
        "cache_write_5m": 3.75,
        "cache_write_1h": 6.00,
        "cache_read": 0.30,
    },
    "sonnet-3.5": {
        "input": 3.00,
        "output": 15.00,
        "cache_write_5m": 3.75,
        "cache_write_1h": 6.00,
        "cache_read": 0.30,
    },
    "haiku-3.5": {
        "input": 0.80,
        "output": 4.00,
        "cache_write_5m": 1.00,
        "cache_write_1h": 1.60,
        "cache_read": 0.08,
    },
    "haiku-3": {
        "input": 0.25,
        "output": 1.25,
        "cache_write_5m": 0.30,
        "cache_write_1h": 0.50,
        "cache_read": 0.03,
    },
}

# Fallback rate for a model id that matches no key above (e.g. a model that
# shipped after this build). Without it such traffic is silently costed at
# $0 and the dashboard under-reports spend. Defaults to the Opus-tier rate so
# the estimate errs high rather than invisible; set PRICING_FALLBACK_INPUT=0
# to restore the old "unknown = free" behaviour.
PRICING_FALLBACK = {
    "input": float(os.getenv("PRICING_FALLBACK_INPUT", "5.00")),
    "output": float(os.getenv("PRICING_FALLBACK_OUTPUT", "25.00")),
}
PRICING_FALLBACK.update(
    {
        "cache_write_5m": PRICING_FALLBACK["input"] * 1.25,
        "cache_write_1h": PRICING_FALLBACK["input"] * 2.0,
        "cache_read": PRICING_FALLBACK["input"] * 0.1,
    }
)


def _load_pricing() -> dict[str, dict[str, float]]:
    """Apply env overrides on top of PRICING_DEFAULTS."""
    pricing = {k: dict(v) for k, v in PRICING_DEFAULTS.items()}
    for model_key in pricing:
        env_prefix = "PRICING_" + model_key.upper().replace("-", "_").replace(".", "_")
        for tier in pricing[model_key]:
            override = os.getenv(f"{env_prefix}_{tier.upper()}")
            if override:
                with contextlib.suppress(ValueError):
                    pricing[model_key][tier] = float(override)
    return pricing


PRICING = _load_pricing()


def _normalize_model_key(model: str | None) -> str:
    """Map a Claude model id to a PRICING key.

    Anthropic's id ordering varies between generations:
      - 4.x: family-first, e.g. `claude-sonnet-4-5-20250929`
      - 3.x: version-first, e.g. `claude-3-5-sonnet-20241022`

    We match both `<family>-<version>` and `<version>-<family>` forms,
    using a hyphen-normalized version (so `3.5` lines up with `3-5`).
    Longer keys are checked first so `sonnet-3.5` wins over `sonnet-3`.
    """
    if not model:
        return "unknown"
    m = model.lower().replace(".", "-")
    candidates = sorted(
        PRICING.keys(),
        key=lambda k: len(k.replace(".", "-")),
        reverse=True,
    )
    for key in candidates:
        norm_key = key.replace(".", "-")
        family, _, version = norm_key.partition("-")
        if not version:
            if family in m:
                return key
            continue
        if f"{family}-{version}" in m or f"{version}-{family}" in m:
            return key
    return "unknown"


def _compute_cost(model_key: str, usage: dict) -> float:
    """Compute USD cost for a single /v1/messages response usage block."""
    # Unknown model ids fall back to a configurable rate instead of $0 so a
    # newly released model never silently disappears from the cost total.
    p = PRICING.get(model_key) or PRICING_FALLBACK
    if not p["input"] and not p["output"]:
        return 0.0

    input_t = usage.get("input_tokens", 0) or 0
    output_t = usage.get("output_tokens", 0) or 0
    cache_read = usage.get("cache_read_input_tokens", 0) or 0
    cache_write_total = usage.get("cache_creation_input_tokens", 0) or 0

    cache_write_5m = 0
    cache_write_1h = 0
    cc = usage.get("cache_creation")
    if isinstance(cc, dict):
        cache_write_5m = cc.get("ephemeral_5m_input_tokens", 0) or 0
        cache_write_1h = cc.get("ephemeral_1h_input_tokens", 0) or 0
    if cache_write_5m == 0 and cache_write_1h == 0 and cache_write_total:
        # Older API shape: no breakdown — assume default 5m TTL.
        cache_write_5m = cache_write_total

    cost = (
        input_t * p["input"]
        + output_t * p["output"]
        + cache_read * p["cache_read"]
        + cache_write_5m * p["cache_write_5m"]
        + cache_write_1h * p["cache_write_1h"]
    ) / 1_000_000.0
    return cost
