<div align="center">

# Claude Proxy

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
| **14 Headers Locked** | user-agent, session-id, stainless-*, anthropic-beta, and more |
| **AES-256-GCM Encryption** | Token encrypted with password-derived key (PBKDF2, 600K iterations) |
| **Password on Startup** | Encryption key never stored on disk — entered at launch |
| **Password Verification** | SHA-256 hash check prevents wrong-password silent failures |
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

## Security

### Encryption

| Layer | Detail |
|-------|--------|
| **Key Derivation** | PBKDF2-HMAC-SHA256 — 600,000 iterations + random salt |
| **Cipher** | AES-256-GCM — authenticated encryption |
| **Nonce** | 12 bytes random per encryption |
| **Auth Tag** | GCM tag — tamper detection |
| **Password** | Never written to disk — entered at startup, held in memory only |
| **Verification** | SHA-256 hash check — wrong password caught immediately |

### Headers Spoofed

All devices send identical fingerprints:

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
| `accept-encoding` | Compression support |
| `sec-fetch-mode` | Fetch metadata |

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
├── proxy.py           # Main proxy server (FastAPI)
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

---

<div align="center">
<sub>Built for sharing Claude Code across devices on Windows.</sub>
</div>
