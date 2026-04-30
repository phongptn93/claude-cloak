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

Set `TOKEN_SAVER=true` in `.env` to enable input-token reduction on `/v1/messages` requests. The proxy applies semantic-preserving transforms before forwarding to Anthropic.

### What it does

| Layer | Description |
|-------|-------------|
| **1h prompt cache** | Injects `cache_control: {type: "ephemeral", ttl: "1h"}` on the `system` block + last `tools[]` entry, and appends `extended-cache-ttl-2025-04-11` to `anthropic-beta`. Extends Claude's default 5min cache → 1h, so long Claude Code sessions hit cache far more often (up to 90% input-token reduction on cached portions). |
| **Tool result truncation** | Walks `messages[]`, finds `tool_result` blocks larger than `TOOL_RESULT_MAX_BYTES` in **older** turns (keeps the last `TOOL_RESULT_KEEP_RECENT` turns intact), and head+tail truncates them with a clear marker. Massive bash/read outputs from earlier in the session get compressed without disturbing active context. |

### Config

```env
TOKEN_SAVER=true
CACHE_EXTEND_TTL=true        # Bump cache TTL 5m → 1h on stable prefix
TOOL_RESULT_TRUNCATE=true    # Truncate large tool_result in older turns
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
    "cache_extend_ttl": true,
    "tool_result_truncate": true,
    "tool_result_max_bytes": 8000,
    "requests_optimized": 42,
    "cache_breakpoints_added": 84,
    "tool_results_truncated": 17,
    "bytes_saved": 312045
  }
}
```

Disabled by default — flip `TOKEN_SAVER=true` only when you want it. When OFF, request bodies pass through untouched.

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
| `GET /health` | Returns proxy status: identity captured, headers locked, telemetry blocked count, bodies sanitized count, unknown headers seen |
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
