<div align="center">

# Claude Cloak

**Share one Claude Code account across multiple Windows devices — undetected.**

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![AES-256](https://img.shields.io/badge/Encryption-AES--256--GCM-success)](https://en.wikipedia.org/wiki/Galois/Counter_Mode)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

<img src="https://img.shields.io/badge/Windows-0078D6?logo=windows&logoColor=white" alt="Windows"> <img src="https://img.shields.io/badge/Claude_Code-VS_Code-7C3AED?logo=visual-studio-code" alt="VS Code">

---

*Local transparent proxy that makes all your devices appear as a single machine to Anthropic.*

<img src="assets/screenshot.png" alt="Claude Proxy" width="700">

</div>

## Features

| Feature | Description |
|---------|-------------|
| **Auto-Capture** | Automatically captures auth token + device identity from first login |
| **24+ Headers Locked** | user-agent, session-id, stainless-*, anthropic-*, sec-fetch-*, and more |
| **AES-256-GCM Encryption** | Token encrypted with password-derived key (PBKDF2, 600K iterations) |
| **Telemetry Blocking** | Blocks telemetry/analytics endpoints — no device info leaks |
| **Body Sanitization** | Strips machine_id, hostname, device_id from request bodies |
| **IP Header Stripping** | Removes 15+ IP-leaking headers (X-Forwarded-For, Via, etc.) |
| **Cookie Isolation** | Strips cookies and Set-Cookie to prevent cross-device tracking |
| **Timing Jitter** | Random delays (10-150ms) to mask multi-device request patterns |
| **Response Sanitization** | Strips tracking headers (server-timing, x-trace-id, etc.) from responses |
| **Consistent IDs** | HMAC-based request IDs — all devices generate identical patterns |
| **Error Masking** | Internal errors never leak proxy details to upstream |
| **Token Refresh** | Auto-detects 401 and captures new token on re-login |
| **Auto-Config** | Automatically sets `ANTHROPIC_BASE_URL` in Claude Code settings |
| **Zero Config** | Just run `start.bat` — everything else is automatic |

## Quick Start

### First Device (one-time setup)

```bash
cd client
install.bat       # Install dependencies
start.bat         # Start proxy + auto-config Claude Code
```

Open Claude Code in VS Code and **log in normally**. The proxy captures everything automatically.

### Other Devices

```bash
cd client
install.bat       # Install dependencies
```

Copy the **`.env` file** from the first device, then:

```bash
start.bat         # Start proxy (enter same password)
```

No login needed. The proxy injects the captured token and identity.

## Security Layers

### Layer 1: Header Locking

All devices send identical fingerprints across **24+ headers**:

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

### Layer 2: Telemetry Blocking

Blocks requests to known telemetry/analytics endpoints:

```
v1/telemetry, v1/analytics, v1/log, v1/events,
v1/diagnostics, v1/metrics, v1/track, v1/report,
telemetry, analytics, log_event, sentry, bugsnag
```

Returns fake `200 OK` responses — Claude Code thinks the telemetry was sent.

### Layer 3: Body Sanitization

Strips 25+ device-identifying fields from JSON request bodies:

```
machine_id, device_id, hostname, computer_name, username,
home_dir, os_version, mac_address, hardware_id, installation_id,
instance_id, client_id, workspace_id, vscode_machine_id, ...
```

Also removes entire nested objects like `system_info`, `device_info`, `telemetry`.

### Layer 4: IP Header Stripping

Removes 15+ headers that could leak the real client IP:

```
X-Forwarded-For, X-Real-IP, X-Forwarded-Host, Via,
X-Client-IP, CF-Connecting-IP, True-Client-IP,
X-Cluster-Client-IP, X-Originating-IP, ...
```

### Layer 5: Cookie Isolation

- Strips `Cookie` headers from outgoing requests
- Strips `Set-Cookie` headers from incoming responses
- Prevents any cookie-based device tracking across sessions

### Layer 6: Response Sanitization

Strips tracking/correlation headers from upstream responses:

```
Server-Timing, X-Trace-Id, X-Span-Id, X-Request-Id,
X-Correlation-Id, X-Amzn-Trace-Id, NEL, Report-To, ...
```

### Layer 7: Timing Jitter

Adds random delay (10-150ms) to each request to prevent timing-based detection of multi-device usage. Configurable via `.env`:

```env
TIMING_JITTER=true
TIMING_JITTER_MIN_MS=10
TIMING_JITTER_MAX_MS=150
```

### Layer 8: Error Masking

Error responses never expose internal proxy details — only generic status codes are returned.

### Encryption

| Layer | Detail |
|-------|--------|
| **Key Derivation** | PBKDF2-HMAC-SHA256 — 600,000 iterations + random salt |
| **Cipher** | AES-256-GCM — authenticated encryption |
| **Nonce** | 12 bytes random per encryption |
| **Auth Tag** | GCM tag — tamper detection |
| **Password** | Never written to disk — entered at startup, held in memory only |
| **Verification** | SHA-256 hash check — wrong password caught immediately |

## Token Lifecycle

| State | Trigger | Action |
|-------|---------|--------|
| **No Token** | First launch | Proxy waits for login, captures token from first request |
| **Captured** | Login detected | Token saved to `.env` (encrypted) — copy to other devices |
| **Active** | Normal usage | Token injected into all requests |
| **Expired** | 401 response | Proxy flags expiry, allows refresh on next login |
| **Refreshed** | Re-login | New token saved — copy updated `.env` to other devices |

## Project Structure

```
client/
├── proxy.py           # Main proxy server (FastAPI) — all anonymity layers
├── setup_claude.py    # Auto-config Claude Code settings
├── tray_app.py        # Windows system tray app
├── start.bat          # Launch script (kill old port + start)
├── install.bat        # Dependency installer
├── .env.example       # Config template
├── .env               # Config with captured data (git-ignored)
└── requirements.txt   # Python dependencies
```

## Requirements

- **Python** 3.10+
- **Windows** 10/11
- **Claude Code** (VS Code extension or CLI)

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Port 9999 already in use | `start.bat` auto-kills old process. Or change `LOCAL_PORT` in `.env` |
| Token expired (401) | Re-login on any device, proxy auto-refreshes, copy `.env` |
| Wrong password on startup | 3 attempts max, then proxy exits. Re-run `start.bat` |
| Empty response from API | Check proxy console for error status codes |
| Timing jitter too slow | Reduce `TIMING_JITTER_MAX_MS` in `.env` or set `TIMING_JITTER=false` |

---

<div align="center">
<sub>Built for sharing Claude Code across devices on Windows.</sub>
</div>
