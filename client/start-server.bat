@echo off
:: Claude Cloak - server-mode launcher for a shared VM (Windows).
::
:: Forces DEPLOY_MODE=server, refuses to start without ALLOWED_IPS, and binds
:: the proxy on LOCAL_HOST (default 0.0.0.0) so whitelisted client machines
:: can point their Claude Code at it via ANTHROPIC_BASE_URL=http://<vm>:9999.
::
:: Run once on the VM. Each client just runs `setup_claude.py --remote URL`.

cd /d "%~dp0"

if not exist .env (
    if exist .env.example (
        copy .env.example .env >nul
        echo Created .env from .env.example - edit it before re-running.
        echo Required: DEPLOY_MODE=server, ALLOWED_IPS=..., CAPTURED_* identity.
        pause
        exit /b 1
    )
    echo .env is missing. Aborting.
    pause
    exit /b 1
)

:: Force server mode regardless of what .env says.
set DEPLOY_MODE=server

:: Read LOCAL_PORT from .env (default 9999).
set LOCAL_PORT=9999
for /f "usebackq tokens=1,2 delims==" %%a in (".env") do (
    if /i "%%a"=="LOCAL_PORT" set LOCAL_PORT=%%b
)

:: Sanity check: ALLOWED_IPS must be set in .env.
set ALLOWED_IPS=
for /f "usebackq tokens=1,* delims==" %%a in (".env") do (
    if /i "%%a"=="ALLOWED_IPS" set ALLOWED_IPS=%%b
)
if "%ALLOWED_IPS%"=="" (
    echo.
    echo   ERROR: ALLOWED_IPS is empty in .env.
    echo   Set ALLOWED_IPS=^<comma-separated IPs/CIDRs^> before starting server mode.
    echo   Example: ALLOWED_IPS=203.0.113.5,198.51.100.0/24
    echo.
    pause
    exit /b 1
)

:: Sanity check: CAPTURED_USER_AGENT must be present (warn only).
findstr /b /r "^CAPTURED_USER_AGENT=." .env >nul 2>&1
if errorlevel 1 (
    echo.
    echo   WARNING: no CAPTURED_USER_AGENT in .env.
    echo   Run the proxy in local mode on one machine first to capture identity,
    echo   then copy the CAPTURED_* lines into this VM's .env.
    echo.
)

:: Kill any stale process on the port.
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :%LOCAL_PORT% ^| findstr LISTENING') do (
    taskkill /PID %%a /F >nul 2>&1
)

:: Auto-install dependencies if missing.
python -c "import httpx" >nul 2>&1 || python -m pip install -r requirements.txt

:: Server mode never auto-configures local Claude Code - skip setup_claude.py.
echo Starting Claude Cloak in SERVER mode on port %LOCAL_PORT%...
echo Whitelisted: %ALLOWED_IPS%
echo.
python proxy.py
pause
