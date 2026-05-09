<div align="center">

# Claude Cloak

**Use Claude Code on multiple Windows devices — all appearing as a single machine to Anthropic.**

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

<img src="https://img.shields.io/badge/Windows-0078D6?logo=windows&logoColor=white" alt="Windows"> <img src="https://img.shields.io/badge/Claude_Code-VS_Code-7C3AED?logo=visual-studio-code" alt="VS Code">

---

*Local transparent proxy that intercepts Claude Code API calls and makes all your devices appear as a single machine.*

<img src="assets/screenshot.png" alt="Claude Proxy" width="700">

</div>

## How It Works

Claude Cloak runs a local proxy on `127.0.0.1:9999`. Claude Code is auto-configured to send API requests through this proxy instead of directly to `api.anthropic.com`.

The proxy captures the device fingerprint (23 headers) from the first request, saves it to `.env`, and injects that same fingerprint into all subsequent requests — from any device. Combined with 7 other anonymity layers (telemetry blocking, body sanitization, IP stripping, etc.), Anthropic sees identical traffic from all your devices.

**Authorization is pass-through** — each device handles its own Claude Code login. The proxy only spoofs the device identity, not the auth token.

## Features

| Feature | Description |
|---------|-------------|
| **Auto-Capture** | Captures 23 device identity headers from first Claude Code request |
| **Header Locking** | All devices send identical fingerprint (user-agent, session-id, stainless-*, anthropic-*, sec-fetch-*, etc.) |
| **Telemetry Blocking** | Intercepts 13 telemetry/analytics URL patterns — returns fake `200 OK` |
| **Body Sanitization** | Strips 38 device-identifying fields + 10 nested objects from JSON request bodies |
| **IP Header Stripping** | Removes 15 IP-leaking headers (X-Forwarded-For, Via, CF-Connecting-IP, etc.) |
| **Cookie Isolation** | Strips outgoing `Cookie` + incoming `Set-Cookie` to prevent cross-device tracking |
| **Timing Jitter** | Random delay (10-150ms) per request to mask multi-device timing patterns |
| **Response Sanitization** | Strips 11 tracking headers from responses (Server-Timing, X-Trace-Id, NEL, etc.) |
| **Consistent IDs** | HMAC-SHA256 based IDs — all devices produce identical derived values |
| **Error Masking** | Internal errors never leak proxy details upstream |
| **Auto-Config** | Automatically sets `ANTHROPIC_BASE_URL` in Claude Code settings |
| **System Tray** | Optional Windows system tray app for background operation |
| **Zero Config** | Just run `start.bat` — everything else is automatic |

## Quick Start

### First Device (one-time setup)

```bash
cd client
install.bat       # Install dependencies
start.bat         # Start proxy + auto-config Claude Code
```

Open Claude Code in VS Code and **log in normally**. The proxy captures the device fingerprint automatically and saves it to `.env`.

### Other Devices

```bash
cd client
install.bat       # Install dependencies
```

Copy the **`.env` file** from the first device, then:

```bash
start.bat         # Start proxy + auto-config Claude Code
```

Log in to the same Claude Code account. The proxy replaces your device's fingerprint with the one captured from the first device.

## Security Layers

### Layer 1: Header Locking (23 headers)

All devices send identical fingerprints. Headers are captured from the first request and injected into all subsequent requests. If a client omits a captured header, the proxy adds it automatically.

| Header | Purpose |
|--------|---------|
| `user-agent` | Client version + OS |
| `x-claude-code-session-id` | Session identifier |
| `x-app` | Client type |
| `anthropic-beta` | Feature flags |
| `anthropic-version` | API version |
| `anthropic-dangerous-direct-browser-access` | Browser flag |
| `x-stainless-os` | Operating system |
| `x-stainless-arch` | CPU architecture |
| `x-stainless-runtime` | Runtime environment |
| `x-stainless-runtime-version` | Runtime version |
| `x-stainless-lang` | SDK language |
| `x-stainless-package-version` | SDK version |
| `x-stainless-retry-count` | Retry count |
| `x-stainless-read-timeout` | Read timeout |
| `accept-encoding` | Compression support |
| `accept-language` | Language preference |
| `sec-fetch-mode` | Fetch metadata |
| `sec-fetch-site` | Fetch site origin |
| `sec-fetch-dest` | Fetch destination |
| `origin` | Request origin |
| `referer` | Referrer URL |
| `x-client-version` | Client version |
| `x-client-name` | Client name |

Additionally, `x-request-id` is replaced with a fresh random hex per request to avoid leaking per-device identifiers.

The proxy also warns in the console when it encounters unknown headers not in its known list, so you can decide whether to add them to the capture list.

### Layer 2: Telemetry Blocking (13 patterns)

Intercepts requests matching known telemetry/analytics URL patterns and returns fake `200 OK` responses — Claude Code thinks the telemetry was sent, but nothing reaches Anthropic.

```
v1/telemetry, v1/analytics, v1/log, v1/events,
v1/diagnostics, v1/metrics, v1/track, v1/report,
telemetry, analytics, log_event, sentry, bugsnag
```

### Layer 3: Body Sanitization (38 fields + 10 objects)

Recursively scans JSON request bodies and replaces device-identifying string fields with HMAC-derived consistent fake values (so all devices produce the same replacement).

**Fields replaced (38 variants):**

```
machine_id, device_id, hostname, computer_name, username,
home_dir, os_version, os_release, platform_version, mac_address,
hardware_id, installation_id, instance_id, client_id,
workspace_id, vscode_machine_id, vscode_session_id
(+ camelCase and kebab-case variants of each)
```

**Nested objects emptied (10):**

```
system_info, device_info, machine_info, environment_info,
telemetry, diagnostics
(+ camelCase variants)
```

### Layer 4: IP Header Stripping (15 headers)

Removes headers that could leak the real client IP before forwarding to Anthropic:

```
X-Forwarded-For, X-Real-IP, X-Forwarded-Host, X-Forwarded-Proto,
X-Forwarded-Port, Forwarded, Via, X-Client-IP, CF-Connecting-IP,
True-Client-IP, X-Cluster-Client-IP, X-Originating-IP,
X-Remote-IP, X-Remote-Addr, Proxy-Connection
```

### Layer 5: Cookie Isolation

- Strips `Cookie` headers from outgoing requests
- Strips `Set-Cookie` headers from incoming responses
- Prevents any cookie-based device tracking across sessions

### Layer 6: Response Sanitization (11 tracking headers)

Strips tracking/correlation headers from upstream responses before returning to the client:

```
Server-Timing, X-Trace-Id, X-Span-Id, X-Request-Id,
X-Correlation-Id, X-Amzn-Trace-Id, X-Amzn-RequestId,
X-Ray-Trace-Id, NEL, Report-To, Reporting-Endpoints
```

### Layer 7: Timing Jitter

Adds a random async delay (default 10-150ms) to each request to prevent timing-based detection of multi-device usage. Configurable via `.env`:

```env
TIMING_JITTER=true
TIMING_JITTER_MIN_MS=10
TIMING_JITTER_MAX_MS=150
```

### Layer 8: Error Masking

All error responses return generic messages only — no internal proxy details, stack traces, or implementation info is ever leaked upstream. Error types handled:

- `504 Gateway timeout` — upstream timeout
- `502 Bad gateway` — connection failure
- `500 Internal proxy error` — all other errors

## Token Saver Mode (optional)

Set `TOKEN_SAVER=true` in `.env` to reduce input-token consumption on `/v1/messages`. Disabled by default — when OFF, request bodies pass through untouched.

### What it does

| Layer | Default | Description |
|-------|---------|-------------|
| **1h prompt cache** | ON | Bumps the existing prompt-cache TTL from 5m → 1h on the stable prefix (system block + last tool definition) and appends `extended-cache-ttl-2025-04-11` to `anthropic-beta`. Long Claude Code sessions hit cache far more often → input charged at the 0.1× cache-read rate instead of 1× fresh. |
| **Tool result truncation** | OFF | Walks `messages[]`, head+tail truncates `tool_result` blocks larger than `TOOL_RESULT_MAX_BYTES` in **older** turns (keeps the last `TOOL_RESULT_KEEP_RECENT` turns intact). |

### Safety guards

- **Breakpoint budget**: Anthropic allows at most 4 `cache_control` breakpoints per request. The proxy counts existing breakpoints and only modifies in-place — it never pushes the total above 4 (skips upgrading `system: string` when full).
- **Beta auto-fallback**: if Anthropic returns a 400 that mentions the cache-ttl beta, the proxy latches the beta off for the rest of the process and reverts to default 5m cache. No further failed requests.
- **Recent-turn protection**: tool_result truncation never touches the last `TOOL_RESULT_KEEP_RECENT` turns, preserving active agent context.

### Realistic impact

Input tokens drop ~15–35% on a typical Claude Code session; output is untouched. Since output is ~60–70% of total quota, **total quota reduction is around 8–18%** — useful for multi-device sharing and avoiding rate-limit throttle on Max plans, but not a silver bullet.

### Why tool truncation defaults OFF

Truncating an old `tool_result` is technically lossy: if Claude later needs to re-read that exact bash/read output, it'll have to re-run the command (which costs tokens). On x20 plans where you rarely hit limits, the saving is not worth the risk. Enable it when:
- Running multi-device share on the same quota
- Sessions routinely exceed 30 turns with large bash/read outputs
- You're regularly hitting "usage limit reached"

### Config

```env
TOKEN_SAVER=true
CACHE_EXTEND_TTL=true        # Bump cache TTL 5m → 1h on stable prefix
TOOL_RESULT_TRUNCATE=false   # Off by default; flip on for multi-device / long sessions
TOOL_RESULT_MAX_BYTES=8000   # Threshold to trigger truncation
TOOL_RESULT_HEAD_BYTES=4000  # Bytes kept from start
TOOL_RESULT_TAIL_BYTES=2000  # Bytes kept from end
TOOL_RESULT_KEEP_RECENT=2    # Recent turns left untouched
```

### Stats

`GET /health` returns live counters under `token_saver`:

```json
{
  "token_saver": {
    "enabled": true,
    "cache_extend_ttl_configured": true,
    "cache_extend_ttl_active": true,
    "tool_result_truncate": false,
    "tool_result_max_bytes": 8000,
    "requests_optimized": 42,
    "cache_breakpoints_added": 84,
    "cache_breakpoints_skipped_full": 0,
    "tool_results_truncated": 0,
    "bytes_saved": 312045,
    "tokens_saved_est": 78011,
    "beta_runtime_disabled": false
  }
}
```

`tokens_saved_est` is an approximation (`bytes_saved / 4`); use it as a directional metric, not an exact charge.

## Quota & Cost Tracking

Enabled by default (`QUOTA_TRACKING=true`). The proxy reads two things from every `/v1/messages` response:

1. **`anthropic-ratelimit-*` headers** → live remaining quota (requests, input tokens, output tokens, reset time)
2. **`usage` block** (from streaming SSE `message_start`/`message_delta` or non-streaming JSON) → input/output/cache token counts + computed USD cost

Bytes are never modified — the tap inspects, the proxy still streams the original chunks to the client. A 5 MB safety cap prevents runaway buffers.

### Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /quota` | Compact JSON — `cost_usd_total`, `tokens` (totals), `by_model` breakdown, `rate_limits` (remaining/limit/reset for requests + input + output tokens, plus retry-after) |
| `GET /health` | Full proxy status — includes a `quota` section with the same data |

Example `/quota`:

```json
{
  "cost_usd_total": 1.2345,
  "messages_requests": 42,
  "tokens": {
    "input_tokens": 12000,
    "output_tokens": 8400,
    "cache_creation_input_tokens": 3200,
    "cache_read_input_tokens": 87000
  },
  "by_model": [
    {"model": "sonnet-4", "requests": 38, "input_tokens": 11000, "output_tokens": 7800, "cost_usd": 1.1024},
    {"model": "haiku-4",  "requests":  4, "input_tokens":  1000, "output_tokens":  600, "cost_usd": 0.1321}
  ],
  "rate_limits": {
    "requests_remaining": "1450",
    "requests_limit": "2000",
    "requests_reset": "2026-05-09T12:34:56Z",
    "input_tokens_remaining": "780000",
    "output_tokens_remaining": "120000",
    "retry_after": null,
    "updated_at": "2026-05-09T12:30:14"
  }
}
```

### Pricing

Defaults are public Anthropic list prices (USD per million tokens). Override per-tier via env if Anthropic changes them or you want plan-specific rates:

```env
PRICING_SONNET_4_INPUT=3.00
PRICING_SONNET_4_OUTPUT=15.00
PRICING_SONNET_4_CACHE_WRITE_5M=3.75
PRICING_SONNET_4_CACHE_WRITE_1H=6.00
PRICING_SONNET_4_CACHE_READ=0.30
```

Model keys: `OPUS_4`, `SONNET_4`, `HAIKU_4`, `OPUS_3`, `SONNET_3_7`, `SONNET_3_5`, `HAIKU_3_5`, `HAIKU_3`. Cost calc uses the per-TTL breakdown when Anthropic provides it (`cache_creation.ephemeral_5m_input_tokens` / `ephemeral_1h_input_tokens`); falls back to default 5 m rate when only the legacy aggregate field is present.

### What it's good for

- **Multi-device share**: one dashboard for total spend across all devices using the proxy
- **Avoid surprise rate-limits**: see remaining quota before hitting 429
- **Token-saver verification**: compare `cache_read_input_tokens` (cheap) vs `input_tokens` (full price) to confirm cache hit rate
- **Cost attribution**: `by_model` shows where the spend lands

### Caveats

- Cost numbers are **estimates** based on the configured pricing table; the canonical source remains the Anthropic console.
- Counters live in-memory only — restart the proxy and they reset.
- Requests served from the telemetry-block layer never touch Anthropic, so they're not counted.

## What It Does NOT Do

| | Description |
|---|---|
| ❌ No token capture | `Authorization` header is passed through from each request — the proxy does not store or inject auth tokens |
| ❌ No encryption | Identity data in `.env` is stored in plaintext — protect the file yourself |
| ❌ No account sharing | Each device must log in to Claude Code independently — the proxy only unifies the device fingerprint |
| ❌ No internet exposure | Proxy binds to `127.0.0.1` only — never accessible from the network |

## Project Structure

```
client/
├── proxy.py           # Main proxy server (FastAPI) — all 8 anonymity layers
├── setup_claude.py    # Auto-config Claude Code → proxy URL
├── tray_app.py        # Optional Windows system tray app
├── start.bat          # Launch script (kill old port + start proxy)
├── install.bat        # Dependency installer
├── .env.example       # Config template with all captured header fields
├── .env               # Captured identity + config (git-ignored)
└── requirements.txt   # Python dependencies
```

## Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Returns proxy status: identity captured, headers locked, telemetry blocked count, bodies sanitized count, unknown headers seen, full quota/cost stats |
| `GET /quota` | Compact quota + cost summary (see Quota & Cost Tracking section) |
| `* /{path}` | Proxy catch-all — applies all 8 layers then forwards to `api.anthropic.com/{path}` |

## Requirements

- **Python** 3.10+
- **Windows** 10/11
- **Claude Code** (VS Code extension or CLI)

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Port 9999 already in use | `start.bat` auto-kills old process. Or change `LOCAL_PORT` in `.env` |
| 401 Unauthorized | Your Claude Code auth token expired. Re-login in Claude Code on that device |
| 429 Rate Limited | Too many requests — wait and retry. The proxy logs this in the console |
| Unknown header warning | Proxy detected a new header not in its known list. Check console and decide if it should be captured |
| Timing jitter too slow | Reduce `TIMING_JITTER_MAX_MS` in `.env` or set `TIMING_JITTER=false` |
| Empty response from API | Check proxy console for error status codes |

---

<div align="center">
<sub>Local reverse proxy for consistent device fingerprinting across Claude Code instances on Windows.</sub>
</div>
