"""Model price table and cost computation.

Prices live in ``data/pricing.json`` rather than in code, so a price change
is a data edit reviewed like any other, and a proxy can pick one up without a
release (see ``PRICING_REMOTE_URL`` below). Anthropic publishes no pricing
API — ``GET /v1/models`` carries ids, context windows and capabilities, not
rates — so the table is the source of truth and the remote sync only fetches
a newer copy of the same file.

Each model key holds a list of rates. A rate applies from its
``effective_from`` date (``YYYY-MM-DD``, local time) until the next entry, and
one without a date applies from the beginning, so a known price change can be
scheduled ahead of time. ``PRICING`` always holds today's rates with
``PRICING_<KEY>_<TIER>`` env overrides applied on top.

Tiers: input, output, cache_write_5m, cache_write_1h, cache_read — USD per
million tokens. Model key is matched by substring against the response
``model`` field; longer keys win, so ``opus-5.5`` is picked over ``opus-5``.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import re
from datetime import datetime
from importlib import resources

from .env import data_path

TIERS = ("input", "output", "cache_write_5m", "cache_write_1h", "cache_read")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_KEY_RE = re.compile(r"^[a-z]+-[0-9][0-9.]*$|^[a-z]+$")


class PricingError(ValueError):
    """A pricing document failed validation; the current table stays in use."""


def parse_pricing(doc: object) -> dict[str, list[dict]]:
    """Validate a pricing document and return ``{key: [rate, ...]}``.

    Rates come back sorted by ``effective_from`` (undated first). Anything
    malformed raises PricingError rather than being skipped, because a
    half-applied table would misprice traffic without anyone noticing.
    """
    if not isinstance(doc, dict) or doc.get("schema") != 1:
        raise PricingError("expected a pricing document with schema 1")
    models = doc.get("models")
    if not isinstance(models, dict) or not models:
        raise PricingError("`models` must be a non-empty object")
    table: dict[str, list[dict]] = {}
    for key, rates in models.items():
        if not isinstance(key, str) or not _KEY_RE.match(key):
            raise PricingError(f"invalid model key {key!r}")
        if not isinstance(rates, list) or not rates:
            raise PricingError(f"{key}: expected a non-empty list of rates")
        seen: set[str] = set()
        clean = []
        for rate in rates:
            if not isinstance(rate, dict):
                raise PricingError(f"{key}: rate must be an object")
            eff = rate.get("effective_from", "")
            if eff and (not isinstance(eff, str) or not _DATE_RE.match(eff)):
                raise PricingError(f"{key}: effective_from must be YYYY-MM-DD, got {eff!r}")
            if eff in seen:
                raise PricingError(f"{key}: two rates share effective_from {eff or '(none)'}")
            seen.add(eff)
            row = {"effective_from": eff}
            for tier in TIERS:
                v = rate.get(tier)
                if isinstance(v, bool) or not isinstance(v, (int, float)) or not 0 <= v < 10_000:
                    raise PricingError(f"{key}: {tier} must be a non-negative number")
                row[tier] = float(v)
            clean.append(row)
        table[key] = sorted(clean, key=lambda r: r["effective_from"])
    return table


def rates_on(table: dict[str, list[dict]], key: str, day: str) -> dict[str, float] | None:
    """The rate for ``key`` in force on ``day`` (``YYYY-MM-DD``), or None."""
    current = None
    for rate in table.get(key, ()):
        if rate["effective_from"] <= day:
            current = rate
    if current is None:
        return None
    return {tier: current[tier] for tier in TIERS}


def _load_bundled() -> tuple[dict[str, list[dict]], dict]:
    raw = resources.files("claude_cloak.data").joinpath("pricing.json").read_text(encoding="utf-8")
    doc = json.loads(raw)
    return parse_pricing(doc), doc


# Fallback rate for a model id that matches no key (e.g. a model that shipped
# after this table was updated). Without it such traffic is silently costed
# at $0 and the dashboard under-reports spend. Defaults to the Opus-tier rate
# so the estimate errs high rather than invisible; set
# PRICING_FALLBACK_INPUT=0 to restore the old "unknown = free" behaviour.
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

_BUNDLED_TABLE, _BUNDLED_DOC = _load_bundled()
_table: dict[str, list[dict]] = _BUNDLED_TABLE

# Today's effective rates. Mutated in place on reload so modules that did
# `from .pricing import PRICING` keep seeing the live table.
PRICING: dict[str, dict[str, float]] = {}
_priced_day = ""

PRICING_SOURCE: dict = {
    "origin": "bundled",
    "updated": _BUNDLED_DOC.get("updated"),
    "source": _BUNDLED_DOC.get("source"),
    "remote_url": "",
    "fetched_at": None,
    "last_error": None,
}


def _env_override(key: str, tier: str) -> float | None:
    env_prefix = "PRICING_" + key.upper().replace("-", "_").replace(".", "_")
    raw = os.getenv(f"{env_prefix}_{tier.upper()}")
    if raw:
        with contextlib.suppress(ValueError):
            return float(raw)
    return None


def _rebuild(day: str | None = None) -> None:
    """Recompute PRICING for ``day`` (default today) from the loaded table."""
    global _priced_day
    day = day or datetime.now().strftime("%Y-%m-%d")
    fresh: dict[str, dict[str, float]] = {}
    for key in _table:
        rates = rates_on(_table, key, day)
        if rates is None:
            continue  # every rate for this model is scheduled in the future
        for tier in TIERS:
            override = _env_override(key, tier)
            if override is not None:
                rates[tier] = override
        fresh[key] = rates
    PRICING.clear()
    PRICING.update(fresh)
    _priced_day = day


def install_table(table: dict[str, list[dict]], origin: str, doc: dict | None = None) -> None:
    """Swap in a validated table. Remote rows override and extend the bundled ones."""
    global _table
    merged = dict(_BUNDLED_TABLE)
    merged.update(table)
    _table = merged
    PRICING_SOURCE["origin"] = origin
    if doc:
        PRICING_SOURCE["updated"] = doc.get("updated")
        PRICING_SOURCE["source"] = doc.get("source")
    _rebuild()


def _ensure_today() -> None:
    # A price scheduled with effective_from takes effect at local midnight
    # without a restart. One string compare per request.
    if datetime.now().strftime("%Y-%m-%d") != _priced_day:
        _rebuild()


_rebuild()


def _normalize_model_key(model: str | None) -> str:
    """Map a Claude model id to a PRICING key.

    Anthropic's id ordering varies between generations:
      - 4.x+: family-first, e.g. `claude-sonnet-4-5-20250929`, `claude-opus-5-5`
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


def rates_for(model_key: str) -> dict[str, float]:
    """Today's rates for a PRICING key, or the fallback for an unknown model."""
    _ensure_today()
    return PRICING.get(model_key) or PRICING_FALLBACK


def cost_of(rates: dict[str, float], tokens: dict) -> float:
    """USD for a token bundle (``input_tokens``, ``output_tokens``, cache fields).

    Cache writes without a 5m/1h split are costed at the 5m rate, which is
    the API default TTL.
    """
    input_t = tokens.get("input_tokens", 0) or 0
    output_t = tokens.get("output_tokens", 0) or 0
    cache_read = tokens.get("cache_read_input_tokens", 0) or 0
    cache_write_total = tokens.get("cache_creation_input_tokens", 0) or 0

    cache_write_5m = 0
    cache_write_1h = 0
    cc = tokens.get("cache_creation")
    if isinstance(cc, dict):
        cache_write_5m = cc.get("ephemeral_5m_input_tokens", 0) or 0
        cache_write_1h = cc.get("ephemeral_1h_input_tokens", 0) or 0
    if cache_write_5m == 0 and cache_write_1h == 0 and cache_write_total:
        # Older API shape: no breakdown — assume default 5m TTL.
        cache_write_5m = cache_write_total

    return (
        input_t * rates["input"]
        + output_t * rates["output"]
        + cache_read * rates["cache_read"]
        + cache_write_5m * rates["cache_write_5m"]
        + cache_write_1h * rates["cache_write_1h"]
    ) / 1_000_000.0


def _compute_cost(model_key: str, usage: dict) -> float:
    """Compute USD cost for a single /v1/messages response usage block."""
    # Unknown model ids fall back to a configurable rate instead of $0 so a
    # newly released model never silently disappears from the cost total.
    p = rates_for(model_key)
    if not p["input"] and not p["output"]:
        return 0.0
    return cost_of(p, usage)


def pricing_view() -> dict:
    """Public shape for GET /pricing: where the table came from, and the rates."""
    _ensure_today()
    return {
        **PRICING_SOURCE,
        "effective_on": _priced_day,
        "fallback": dict(PRICING_FALLBACK),
        "models": [
            {
                "model": key,
                **PRICING[key],
                "scheduled": [r for r in _table.get(key, ()) if r["effective_from"] > _priced_day],
            }
            for key in sorted(PRICING)
        ],
    }


# ---------------------------------------------------------------------------
# Optional remote sync
# ---------------------------------------------------------------------------
# Off unless PRICING_REMOTE_URL is set. When on, the proxy fetches a pricing
# document in the same format (e.g. this repository's data/pricing.json on
# the default branch), validates it, and merges it over the bundled table —
# so a price fix reaches every install within PRICING_REMOTE_REFRESH_HOURS
# without an upgrade. The last good copy is cached next to .quota.json and
# reused at startup; a failed fetch or a document that fails validation
# leaves the current table in place.
PRICING_REMOTE_URL = os.getenv("PRICING_REMOTE_URL", "").strip()
PRICING_SOURCE["remote_url"] = PRICING_REMOTE_URL


def _refresh_hours() -> float:
    try:
        return max(1.0, float(os.getenv("PRICING_REMOTE_REFRESH_HOURS", "24")))
    except ValueError:
        return 24.0


def _cache_path() -> str:
    return data_path(".pricing-remote.json", os.getenv("PRICING_REMOTE_CACHE_PATH", ""))


def load_cached_remote() -> bool:
    """Install the last successfully fetched remote table, if there is one."""
    if not PRICING_REMOTE_URL or not os.path.exists(_cache_path()):
        return False
    try:
        with open(_cache_path(), encoding="utf-8") as f:
            doc = json.load(f)
        table = parse_pricing(doc)
    except (OSError, ValueError):
        return False
    install_table(table, "remote-cache", doc)
    return True


async def refresh_remote_pricing(client=None) -> bool:
    """Fetch, validate and install the remote table. Never raises."""
    if not PRICING_REMOTE_URL:
        return False
    import httpx  # local: only needed when the feature is on

    own = client is None
    client = client or httpx.AsyncClient(timeout=15.0, follow_redirects=True)
    try:
        resp = await client.get(PRICING_REMOTE_URL, headers={"accept": "application/json"})
        resp.raise_for_status()
        doc = resp.json()
        table = parse_pricing(doc)
    except Exception as exc:  # network, HTTP status, JSON or schema failure
        PRICING_SOURCE["last_error"] = f"{type(exc).__name__}: {exc}"[:300]
        return False
    finally:
        if own:
            await client.aclose()
    install_table(table, "remote", doc)
    PRICING_SOURCE["fetched_at"] = datetime.now().isoformat(timespec="seconds")
    PRICING_SOURCE["last_error"] = None
    tmp = _cache_path() + ".tmp"
    with contextlib.suppress(OSError):
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(doc, f, ensure_ascii=False, indent=2)
        os.replace(tmp, _cache_path())
    return True


async def remote_pricing_loop() -> None:
    """Refresh the remote table at startup and then every refresh interval."""
    while True:
        await refresh_remote_pricing()
        await asyncio.sleep(_refresh_hours() * 3600)
