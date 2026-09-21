# Changelog

Notable changes to Claude Cloak. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1] — Unreleased

### Added

- **Proxy access keys** — a second door beside `ALLOWED_IPS`, for clients whose
  address is dynamic. A key is a high-entropy secret the client carries in its
  base URL (`ANTHROPIC_BASE_URL=https://vm:9999/k/<key>`) or in
  `PROXY_KEY_HEADER`; it admits the caller from any address and names the user,
  so per-user attribution and caps work exactly as they do for a whitelisted IP.
  Off by default (`PROXY_KEYS_ENABLED`) — it widens who can reach the proxy, so
  it is an `.env` decision rather than a web-console one.
  - **`/keys` console** to issue, disable, re-date and revoke keys per user,
    with each user's spend against their cap. Same two gates as `/config`: an
    IP in `ADMIN_IPS`, then `ADMIN_TOKEN`. Only the SHA-256 of a key is stored
    (`.keys.json`, `0600`); the plaintext is shown once, at creation.
  - A key never opens `/config`, `/keys` or `/admin/*`, never reaches upstream
    (URL segment stripped before routing, header stripped before forwarding),
    and never appears in a log line — a rejection records four characters and
    the reason.
  - A key outranks a `/u/<label>/` prefix, so its holder cannot bill traffic to
    someone else's bucket.
  - `GET /whoami` answers "who am I to this proxy, and what is my cap" for a
    keyed client. `GET /u/<label>/whoami` now reports the label that will
    actually be billed, with the requested one alongside as `url_label`.
  - Server mode now boots with an empty `ALLOWED_IPS` when keys are enabled and
    at least one is active, instead of aborting.

### Fixed

- **One vanishing client could stop the proxy accepting connections, on
  Windows.** asyncio's default loop there is the proactor, and CPython treats
  any `accept()` error as fatal for the *listening* socket — it calls the
  exception handler and then `sock.close()`. A client that disappears between
  the TCP handshake and accept (`[WinError 64] The specified network name is
  no longer available`), which a port open to the internet sees daily, was
  therefore enough to leave the process up, the dashboard answering on
  already-open connections, and every new client refused until a restart. The
  proxy now serves on the selector loop on Windows, which logs a failed accept
  and keeps going; `WINDOWS_EVENT_LOOP=proactor` restores the stdlib choice.
- **Console noise from a public port.** A dropped connection printed a
  multi-frame `Task exception was never retrieved` traceback, and each
  non-HTTP request a bare `Invalid HTTP request received.` — a scanner buried
  the request log in both. Both are now one rate-limited line
  (`NETWORK_NOISE_WARN_INTERVAL`) that names the likely cause, with running
  totals in `listener` in `/health`. The commonest cause is a client using
  `https://` against a plain-HTTP listener, which the message now says.
- **The `/config` console offered quota periods the code rejects.**
  `USER_QUOTA_PERIOD` listed `day`/`week`/`month` while `settings.py` accepts
  only `daily`/`monthly` and normalises everything else to monthly. All three
  offered values were silent no-ops: the console asked for a restart, and the
  restart discarded the choice. A test now walks every spec with `choices` and
  asserts the settings module keeps the value.
- **`SESSION_SECRET` was regenerated on every start in server mode**, so every
  `/config` sign-in died on restart — including the restart each certificate
  renewal triggers. The secret was only persisted inside identity capture,
  which server mode disables by design. It is now written once from the app
  lifespan, which every deployment path runs.

## [0.2.0] — 2026-09-03

The first packaged release. Everything before this lived as a single
5,365-line `client/proxy.py` with a `requirements.txt`, no lockfile, no tests
and no linter.

Observable behaviour is unchanged: every endpoint path, JSON response shape
and `.env` key is the same as before. Golden snapshots of `/health`, `/quota`,
`/quota/users`, `/coach`, `/config/data`, `/dashboard` and `/config` were
captured from the pre-refactor process and are asserted on every CI run.

### Added

- **uv project.** `pyproject.toml` + `uv.lock` replace `requirements.txt`.
  Console scripts `claude-cloak`, `claude-cloak-setup`, `claude-cloak-tray`.
  `requires-python = ">=3.11"`.
- **Test suite** — 96 tests, including golden endpoint contracts, and the
  gates `ruff check`, `ruff format --check`, `ty check`.
- **Continuous integration** (`.github/workflows/ci.yml`) on every push and
  pull request: the four gates on Python 3.11 and 3.13, `shellcheck` over
  every tracked `*.sh`, a bundle install in a bare `ubuntu:24.04` container
  with no uv/git/compiler, and a Docker image build.
- **Release pipeline** (`.github/workflows/release.yml`) on a `v*` tag:
  refuses a tag that disagrees with the project version, publishes a bundle
  with `SHA256SUMS` and a signed build-provenance attestation.
- **`deploy/install-from-release.sh`** — installs a published bundle on a
  host with no clone and no build. Refuses to install on a checksum mismatch;
  verifies the attestation when `gh` is available; honours `BASE_URL` for an
  internal mirror.
- **Deployment targets** — systemd unit (hardened sandbox,
  `CAP_NET_BIND_SERVICE`), Docker image and compose file, Windows service
  installer.
- **Native TLS.** The proxy terminates TLS itself, so no reverse proxy hop
  distorts the client address every IP gate depends on. `TLS_CERTFILE`,
  `TLS_KEYFILE`, `HTTP_REDIRECT_PORT`, `PUBLIC_HOSTNAME`, `PUBLIC_HTTPS_PORT`.
- **ACME listener** — serves `/.well-known/acme-challenge/` on port 80 and
  redirects everything else to HTTPS, so Let's Encrypt renewal works with the
  proxy holding the port. `/health` reports certificate expiry, so a renewal
  that stopped working is visible before it becomes an outage.
- **`TRUSTED_PROXY_IPS`** — opt-in `X-Forwarded-For` handling for deployments
  that do need a front proxy. The rightmost untrusted entry wins, which is the
  last one a client cannot forge.
- **`DEV_ECHO_MODE`** — the proxy answers `/v1/*` itself with a synthetic
  Anthropic-shaped response (SSE when the request streams). The whole
  pipeline is exercisable with no API key, no network and no spend.
- **`ANTHROPIC_UPSTREAM_URL`** — forward somewhere other than
  `api.anthropic.com`.
- **Azure deployment guide** — public IP + DNS label + Let's Encrypt, verified
  end to end on a live VM. Includes running alongside a second HTTPS service.

### Changed

- **`.env` and `.env.example` moved to the repository root.** They lived in
  `client/` because the proxy source did; the package now lives in `src/` and
  `client/` holds only launchers and shims. Resolution prefers the root file,
  and every launcher `cd`s to the root, so the file they bootstrap is the file
  the package reads.
- **Package split** — the monolith became 40 modules under
  `src/claude_cloak/`. All configuration lives in `settings.py` and all
  mutable state in `state.py`; there are no `global` statements left. The
  1,645 lines of embedded HTML moved to `web/*.html` byte-for-byte.
- **Every hardcoded tunable is now configuration** — cache beta id, buffer
  caps, retry backoff, cookie name, and more. Static tables (telemetry paths,
  sanitized fields, header policies, coach tool names) accept `<NAME>_EXTRA`
  to append or `<NAME>_OVERRIDE` to replace.
- **Dependencies upgraded** — FastAPI 0.115 → 0.141, httpx 0.27 → 0.28,
  uvicorn 0.30 → 0.52, python-dotenv 1.0 → 1.2. Tray dependencies moved to a
  `tray` extra.
- Launcher scripts are uv-only; the pip fallback is gone.

### Fixed

- **Brotli and zstd responses were corrupted.** httpx was installed without
  its compression extras, so it could not decode `br`/`zstd` bodies, while the
  proxy stripped the `content-encoding` header that would have let the client
  do it. Now `httpx[brotli,zstd]`, asserted in CI on the installed artifact.
- **An empty `.env` value fell back to the default.** `TIMING_JITTER=` meant
  "off" before configuration was centralised and means "off" again.
- **`save_to_env` wrote into commented sample lines**, silently losing the
  value. The pattern is now anchored to the start of a line.
- **Renewed certificates were unreadable by the service.** ACLs on
  `/etc/letsencrypt` do not inherit to the new `privkey` certbot writes each
  renewal, which crash-looped the service. A deploy hook now copies the
  renewed pair into the service's own data directory and restarts it.

### Known limitations

- The proxy holds all counters in process memory. **Never run more than one
  worker or replica** — a second instance splits every counter.
- `/u/<label>/` is identification, not authentication: any whitelisted caller
  can claim any label. The IP whitelist is the actual gate.
- The Windows service installer has not been exercised on a real Windows host.
