"""
Claude Proxy - Tất cả máy giả lập 1 thiết bị duy nhất.

Flow:
  - Máy đầu tiên: login Claude Code → proxy tự bắt TOÀN BỘ identity → lưu .env (mã hóa)
  - Các máy khác: copy .env → proxy inject identity đã bắt

Security:
  - Token được mã hóa trong .env (AES)
  - Lock toàn bộ fingerprint headers
"""

import base64
import hashlib
import json
import logging
import os
import re
import sys
import time
from contextlib import asynccontextmanager
from datetime import datetime

import httpx
import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import StreamingResponse

# Enable ANSI colors on Windows
if sys.platform == "win32":
    os.system("")

ENV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
load_dotenv(ENV_PATH)

# ============================================================
# PASSWORD PROMPT - Nhập khi khởi động, không lưu vào file
# ============================================================
def prompt_password() -> str:
    """Hỏi password khi khởi động. Bỏ trống = không mã hóa."""
    if sys.platform == "win32":
        os.system("")
    print()
    print(f"  \033[36m\033[1mClaude Proxy\033[0m")
    print(f"  \033[2m{'─' * 40}\033[0m")
    print(f"  \033[2mNhap password de ma hoa token (Enter = bo qua):\033[0m")
    try:
        import getpass
        password = getpass.getpass(f"  \033[33mPassword: \033[0m")
    except (EOFError, KeyboardInterrupt):
        password = ""
    return password.strip()


# Check .env có token đã mã hóa chưa
_raw_token = os.getenv("AUTH_TOKEN", "")
_has_encrypted_data = _raw_token.startswith("ENC:")
_password_hash = os.getenv("PASSWORD_HASH", "")

if _has_encrypted_data:
    # Có dữ liệu mã hóa → bắt buộc nhập password + verify
    MAX_ATTEMPTS = 3
    ENCRYPT_KEY = ""
    for attempt in range(MAX_ATTEMPTS):
        ENCRYPT_KEY = prompt_password()
        if not ENCRYPT_KEY:
            print(f"  \033[31mToken da ma hoa, bat buoc nhap password!\033[0m")
            continue
        # Verify password bằng hash đã lưu
        if _password_hash:
            import hashlib as _hl
            check = _hl.sha256(ENCRYPT_KEY.encode()).hexdigest()[:16]
            if check == _password_hash:
                print(f"  \033[32mPassword chinh xac!\033[0m")
                print()
                break
            else:
                remaining = MAX_ATTEMPTS - attempt - 1
                print(f"  \033[31mSai password! Con {remaining} lan thu.\033[0m")
                ENCRYPT_KEY = ""
                if remaining == 0:
                    print(f"  \033[31mHet so lan thu. Proxy thoat.\033[0m")
                    sys.exit(1)
        else:
            # Không có hash (file .env cũ) → chấp nhận
            break
elif _raw_token:
    # Có token plaintext → hỏi muốn mã hóa không
    ENCRYPT_KEY = prompt_password()
else:
    # Chưa có gì → hỏi muốn mã hóa không
    ENCRYPT_KEY = prompt_password()

# ============================================================
# ANSI Colors
# ============================================================
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
WHITE = "\033[37m"

BG_GREEN = "\033[42m"
BG_RED = "\033[41m"
BG_YELLOW = "\033[43m"
BG_CYAN = "\033[46m"

# ============================================================
# Custom Logger
# ============================================================
class ColorFormatter(logging.Formatter):
    def format(self, record):
        if record.name in ("uvicorn.access", "httpx"):
            return ""
        return record.getMessage()


logger = logging.getLogger("claude_proxy")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(ColorFormatter())
logger.addHandler(handler)

logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
logging.getLogger("httpx").setLevel(logging.WARNING)

LOCAL_PORT = int(os.getenv("LOCAL_PORT", "9999"))
ANTHROPIC_BASE_URL = "https://api.anthropic.com"

# ============================================================
# ENCRYPTION - AES-256-GCM + PBKDF2-HMAC-SHA256
# ============================================================
SALT_SIZE = 16
NONCE_SIZE = 12
PBKDF2_ITERATIONS = 600_000


def derive_key(password: str, salt: bytes) -> bytes:
    """PBKDF2-HMAC-SHA256 → 32 bytes (AES-256 key)."""
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)


def encrypt_value(value: str, password: str) -> str:
    """AES-256-GCM encrypt. Output: ENC:<base64(salt + nonce + tag + ciphertext)>"""
    if not password:
        return value
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        salt = os.urandom(SALT_SIZE)
        key = derive_key(password, salt)
        nonce = os.urandom(NONCE_SIZE)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, value.encode("utf-8"), None)
        # ciphertext includes 16-byte GCM tag appended
        payload = salt + nonce + ciphertext
        return "ENC:" + base64.b64encode(payload).decode("ascii")
    except Exception:
        return value


def decrypt_value(value: str, password: str) -> str:
    """AES-256-GCM decrypt."""
    if not password or not value.startswith("ENC:"):
        return value
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        payload = base64.b64decode(value[4:])
        salt = payload[:SALT_SIZE]
        nonce = payload[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
        ciphertext = payload[SALT_SIZE + NONCE_SIZE:]
        key = derive_key(password, salt)
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode("utf-8")
    except Exception:
        return value


# ============================================================
# CAPTURED IDENTITY - Bắt từ request thật
# ============================================================
CAPTURE_HEADERS = [
    "user-agent",
    "x-claude-code-session-id",
    "x-app",
    "anthropic-beta",
    "anthropic-version",
    "anthropic-dangerous-direct-browser-access",
    "x-stainless-os",
    "x-stainless-arch",
    "x-stainless-runtime",
    "x-stainless-runtime-version",
    "x-stainless-lang",
    "x-stainless-package-version",
    "accept-encoding",
    "sec-fetch-mode",
]


def env_key(header: str) -> str:
    return "CAPTURED_" + header.upper().replace("-", "_")


captured_identity: dict[str, str] = {}
for h in CAPTURE_HEADERS:
    val = os.getenv(env_key(h), "")
    if val:
        captured_identity[h] = decrypt_value(val, ENCRYPT_KEY)

AUTH_TOKEN = decrypt_value(os.getenv("AUTH_TOKEN", ""), ENCRYPT_KEY)
identity_captured = bool(captured_identity)

# ============================================================
# CLAUDE CREDENTIALS SYNC - Skip login trên máy khác
# ============================================================
CLAUDE_DIR = os.path.join(os.path.expanduser("~"), ".claude")
CLAUDE_CREDS_PATH = os.path.join(CLAUDE_DIR, ".credentials.json")


def sync_claude_credentials():
    """
    Đồng bộ ~/.claude/.credentials.json <-> .env

    - Máy đã login: đọc .credentials.json → mã hóa lưu vào .env
    - Máy mới (copy .env): giải mã từ .env → ghi ra .credentials.json → skip login
    """
    raw_creds_env = os.getenv("CLAUDE_CREDENTIALS", "")
    has_creds_env = bool(raw_creds_env)
    has_creds_file = os.path.exists(CLAUDE_CREDS_PATH)

    if has_creds_file and not has_creds_env:
        # Máy đã login → capture credentials vào .env
        try:
            with open(CLAUDE_CREDS_PATH, "r", encoding="utf-8") as f:
                creds_json = f.read().strip()
            if creds_json:
                save_to_env("CLAUDE_CREDENTIALS", creds_json)
                print(f"  {GREEN}Credentials captured tu {CLAUDE_CREDS_PATH}{RESET}")
                print(f"  {YELLOW}Da luu vao .env (ma hoa) - Copy sang cac may khac!{RESET}")
                print()
        except OSError:
            pass

    elif has_creds_env and not has_creds_file:
        # Máy mới, có credentials trong .env → ghi ra file để skip login
        try:
            creds_json = decrypt_value(raw_creds_env, ENCRYPT_KEY)
            # Validate JSON
            json.loads(creds_json)
            os.makedirs(CLAUDE_DIR, exist_ok=True)
            with open(CLAUDE_CREDS_PATH, "w", encoding="utf-8") as f:
                f.write(creds_json)
            # Set file permission 600 trên Linux
            if sys.platform != "win32":
                os.chmod(CLAUDE_CREDS_PATH, 0o600)
            print(f"  {GREEN}Credentials restored → {CLAUDE_CREDS_PATH}{RESET}")
            print(f"  {GREEN}Claude Code se skip login!{RESET}")
            print()
        except (json.JSONDecodeError, OSError) as e:
            print(f"  {RED}Loi restore credentials: {e}{RESET}")
            print()


sync_claude_credentials()

http_client: httpx.AsyncClient | None = None
request_count = 0


def log(msg: str):
    logger.info(msg)


def save_password_hash():
    """Lưu hash của password vào .env để verify lần sau."""
    if not ENCRYPT_KEY:
        return
    pw_hash = hashlib.sha256(ENCRYPT_KEY.encode()).hexdigest()[:16]
    save_to_env("PASSWORD_HASH", pw_hash)


def save_to_env(key: str, value: str):
    """Lưu hoặc cập nhật 1 key trong .env file (mã hóa nếu có ENCRYPT_KEY)."""
    encrypted_keys = {"AUTH_TOKEN", "CLAUDE_CREDENTIALS"}
    store_value = encrypt_value(value, ENCRYPT_KEY) if key in encrypted_keys else value

    if not os.path.exists(ENV_PATH):
        with open(ENV_PATH, "w") as f:
            f.write(f"{key}={store_value}\n")
        return

    with open(ENV_PATH, "r") as f:
        content = f.read()

    if f"{key}=" in content:
        content = re.sub(rf"{re.escape(key)}=.*", f"{key}={store_value}", content)
    else:
        content = content.rstrip("\n") + f"\n{key}={store_value}\n"

    with open(ENV_PATH, "w") as f:
        f.write(content)


def capture_identity_from_request(request: Request):
    global identity_captured, captured_identity

    if identity_captured:
        return

    req_headers = {k.lower(): v for k, v in request.headers.items()}

    for h in CAPTURE_HEADERS:
        val = req_headers.get(h, "")
        if val:
            captured_identity[h] = val
            save_to_env(env_key(h), val)

    if captured_identity:
        identity_captured = True
        log("")
        log(f"  {BG_GREEN}{BOLD} IDENTITY CAPTURED {RESET}")
        log(f"  {GREEN}Da bat {len(captured_identity)} headers tu Claude Code:{RESET}")
        for h, v in captured_identity.items():
            display = mask_value(v, 40) if len(v) > 50 else v
            log(f"    {MAGENTA}{h}{RESET}: {WHITE}{display}{RESET}")
        log(f"  {YELLOW}Da luu vao .env - Copy sang cac may khac!{RESET}")
        log("")


def capture_auth_from_request(request: Request):
    """Chỉ bắt token khi CHƯA CÓ. Không ghi đè token đã có."""
    global AUTH_TOKEN

    if AUTH_TOKEN:
        return  # Đã có token → không bắt lại

    req_headers = {k.lower(): v for k, v in request.headers.items()}
    incoming_auth = req_headers.get("authorization", "")

    if not incoming_auth:
        return

    AUTH_TOKEN = incoming_auth
    save_to_env("AUTH_TOKEN", incoming_auth)
    save_password_hash()

    encrypted_note = f" {GREEN}(encrypted){RESET}" if ENCRYPT_KEY else f" {YELLOW}(plaintext){RESET}"
    log("")
    log(f"  {BG_GREEN}{BOLD} TOKEN CAPTURED {RESET}{encrypted_note}")
    log(f"  {GREEN}Auth token da luu vao .env{RESET}")
    log(f"  {YELLOW}Copy file .env sang cac may khac!{RESET}")
    log("")


def refresh_auth_from_request(request: Request):
    """Cập nhật token MỚI khi token cũ bị 401 (hết hạn)."""
    global AUTH_TOKEN

    req_headers = {k.lower(): v for k, v in request.headers.items()}
    incoming_auth = req_headers.get("authorization", "")

    if not incoming_auth or incoming_auth == AUTH_TOKEN:
        return

    AUTH_TOKEN = incoming_auth
    save_to_env("AUTH_TOKEN", incoming_auth)
    save_password_hash()

    encrypted_note = f" {GREEN}(encrypted){RESET}" if ENCRYPT_KEY else f" {YELLOW}(plaintext){RESET}"
    log("")
    log(f"  {BG_GREEN}{BOLD} TOKEN REFRESHED {RESET}{encrypted_note}")
    log(f"  {GREEN}Token moi da luu vao .env{RESET}")
    log(f"  {YELLOW}Copy file .env sang cac may khac!{RESET}")
    log("")


def print_banner():
    banner = f"""
{MAGENTA}{BOLD}
     ██████╗██╗      █████╗ ██╗   ██╗██████╗ ███████╗
    ██╔════╝██║     ██╔══██╗██║   ██║██╔══██╗██╔════╝
    ██║     ██║     ███████║██║   ██║██║  ██║█████╗
    ██║     ██║     ██╔══██║██║   ██║██║  ██║██╔══╝
    ╚██████╗███████╗██║  ██║╚██████╔╝██████╔╝███████╗
     ╚═════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝
{RESET}{CYAN}{BOLD}               ██████╗ ██████╗  ██████╗ ██╗  ██╗██╗   ██╗
               ██╔══██╗██╔══██╗██╔═══██╗╚██╗██╔╝╚██╗ ██╔╝
               ██████╔╝██████╔╝██║   ██║ ╚███╔╝  ╚████╔╝
               ██╔═══╝ ██╔══██╗██║   ██║ ██╔██╗   ╚██╔╝
               ██║     ██║  ██║╚██████╔╝██╔╝ ██╗   ██║
               ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝{RESET}
"""
    print(banner)


def mask_value(val: str, show=12) -> str:
    if len(val) <= show + 4:
        return val
    return f"{val[:show]}...{val[-4:]}"


def print_status():
    token_status = f"{GREEN}Ready{RESET}" if AUTH_TOKEN else f"{YELLOW}Waiting for login...{RESET}"
    identity_status = f"{GREEN}{len(captured_identity)} headers locked{RESET}" if identity_captured else f"{YELLOW}Waiting for first request...{RESET}"
    encrypt_status = f"{GREEN}ON (password protected){RESET}" if ENCRYPT_KEY else f"{DIM}OFF (Enter de bo qua){RESET}"

    print(f"  {DIM}{'─' * 60}{RESET}")
    print(f"  {CYAN} Server      {RESET}{WHITE}http://localhost:{LOCAL_PORT}{RESET}")
    print(f"  {CYAN} Target      {RESET}{WHITE}{ANTHROPIC_BASE_URL}{RESET}")
    print(f"  {DIM}{'─' * 60}{RESET}")
    print(f"  {CYAN} Token       {RESET}{token_status}")
    print(f"  {CYAN} Identity    {RESET}{identity_status}")
    print(f"  {CYAN} Encryption  {RESET}{encrypt_status}")
    if identity_captured:
        print(f"  {DIM}{'─' * 60}{RESET}")
        for h, v in captured_identity.items():
            display = mask_value(v, 40) if len(v) > 50 else v
            print(f"  {DIM}  {h}: {MAGENTA}{display}{RESET}")
    print(f"  {DIM}{'─' * 60}{RESET}")
    print()


@asynccontextmanager
async def lifespan(app: FastAPI):
    global http_client
    http_client = httpx.AsyncClient(timeout=httpx.Timeout(300.0, connect=10.0))
    print_banner()
    print_status()
    yield
    await http_client.aclose()


app = FastAPI(title="Claude Proxy", lifespan=lifespan)


# Headers không forward từ upstream response
EXCLUDED_RESPONSE_HEADERS = {
    "content-length", "transfer-encoding", "content-encoding",
    "connection", "keep-alive",
}

# Headers không forward từ client request
EXCLUDED_REQUEST_HEADERS = {
    "host", "content-length", "transfer-encoding",
}


def build_request_headers(request: Request) -> dict[str, str]:
    headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in EXCLUDED_REQUEST_HEADERS
    }

    # Override identity headers
    if captured_identity:
        for k in list(headers.keys()):
            kl = k.lower()
            if kl in captured_identity:
                headers[k] = captured_identity[kl]

    # Override auth token
    if AUTH_TOKEN:
        auth_key = next((k for k in headers if k.lower() == "authorization"), None)
        if auth_key:
            headers[auth_key] = AUTH_TOKEN
        else:
            headers["Authorization"] = AUTH_TOKEN

    return headers


def filter_response_headers(response: httpx.Response) -> dict[str, str]:
    return {
        k: v for k, v in response.headers.items()
        if k.lower() not in EXCLUDED_RESPONSE_HEADERS
    }


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "has_token": bool(AUTH_TOKEN),
        "identity_captured": identity_captured,
        "headers_locked": len(captured_identity),
        "encryption": bool(ENCRYPT_KEY),
    }


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"])
async def proxy(path: str, request: Request):
    global request_count
    request_count += 1
    req_id = request_count

    # Auto-capture identity + token
    capture_identity_from_request(request)
    capture_auth_from_request(request)

    target_url = f"{ANTHROPIC_BASE_URL}/{path}"
    headers = build_request_headers(request)
    body = await request.body()

    now = datetime.now().strftime("%H:%M:%S")
    start_time = time.monotonic()

    # Request log
    log(f"  {DIM}{now}{RESET}  {CYAN}{BOLD}#{req_id}{RESET}  {BLUE}{BOLD}{request.method}{RESET} /{path}")

    # Headers log
    sensitive = {"authorization", "x-api-key", "cookie"}
    spoofed = set(captured_identity.keys())
    for k, v in headers.items():
        kl = k.lower()
        if kl in sensitive:
            log(f"           {DIM}{k}: {RESET}{YELLOW}{mask_value(v)}{RESET}")
        elif kl in spoofed:
            log(f"           {DIM}{k}: {RESET}{MAGENTA}{mask_value(v, 40)}{RESET} {DIM}(locked){RESET}")
        else:
            log(f"           {DIM}{k}: {v}{RESET}")

    try:
        req = http_client.build_request(
            method=request.method,
            url=target_url,
            headers=headers,
            content=body,
            params=dict(request.query_params),
        )
        response = await http_client.send(req, stream=True)

        elapsed = time.monotonic() - start_time
        status = response.status_code

        if 200 <= status < 300:
            status_str = f"{BG_GREEN}{BOLD} {status} {RESET}"
        elif status == 401:
            status_str = f"{BG_RED}{BOLD} {status} UNAUTHORIZED {RESET}"
            log(f"           {RED}{BOLD}TOKEN HET HAN! Login lai tren 1 may bat ky{RESET}")
            # Token hết hạn → cho phép bắt token mới từ request tiếp theo
            refresh_auth_from_request(request)
        elif status == 429:
            status_str = f"{BG_YELLOW}{BOLD} {status} RATE LIMITED {RESET}"
            log(f"           {YELLOW}Qua nhieu request - doi mot chut...{RESET}")
        elif 400 <= status < 500:
            status_str = f"{BG_YELLOW}{BOLD} {status} {RESET}"
        else:
            status_str = f"{BG_RED}{BOLD} {status} {RESET}"

        log(f"  {DIM}{now}{RESET}  {CYAN}{BOLD}#{req_id}{RESET}  {status_str} {DIM}{elapsed:.1f}s{RESET}")
        log("")

        response_headers = filter_response_headers(response)

        async def stream_response():
            try:
                async for chunk in response.aiter_bytes():
                    yield chunk
            finally:
                await response.aclose()

        return StreamingResponse(
            stream_response(),
            status_code=response.status_code,
            headers=response_headers,
            media_type=response.headers.get("content-type"),
        )

    except httpx.TimeoutException:
        log(f"  {DIM}{now}{RESET}  {CYAN}{BOLD}#{req_id}{RESET}  {BG_RED}{BOLD} TIMEOUT {RESET}")
        log("")
        raise HTTPException(status_code=504, detail="Upstream API timeout")
    except httpx.ConnectError:
        log(f"  {DIM}{now}{RESET}  {CYAN}{BOLD}#{req_id}{RESET}  {BG_RED}{BOLD} CONNECT ERROR {RESET}")
        log("")
        raise HTTPException(status_code=502, detail="Cannot connect to upstream API")
    except Exception as e:
        log(f"  {DIM}{now}{RESET}  {CYAN}{BOLD}#{req_id}{RESET}  {BG_RED}{BOLD} ERROR {RESET} {RED}{e}{RESET}")
        log("")
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=LOCAL_PORT,
        log_level="warning",
    )
