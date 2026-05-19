@echo off
:: Claude Cloak - server-mode launcher for a shared VM (Windows).
::
:: Interactive setup the first time it runs: prompts for ALLOWED_IPS and
:: (optionally) IP_LABELS + per-user spend caps, then writes .env and boots
:: the proxy. On subsequent runs it just boots — re-runs the wizard only
:: when ALLOWED_IPS is missing.
::
:: After the first /v1/messages request from a whitelisted device, the proxy
:: auto-captures that device's identity headers and locks them in .env for
:: every other device.

setlocal EnableDelayedExpansion
cd /d "%~dp0"

if not exist .env (
    if exist .env.example (
        copy .env.example .env >nul
        echo Created .env from .env.example
    ) else (
        echo LOCAL_PORT=9999> .env
        echo DEPLOY_MODE=server>> .env
    )
)

:: Force server mode for this process (overrides whatever's in .env).
set DEPLOY_MODE=server

:: ── Read LOCAL_PORT + ALLOWED_IPS from .env ───────────────────────────────
set LOCAL_PORT=9999
set ALLOWED_IPS=
for /f "usebackq tokens=1,* delims==" %%a in (".env") do (
    if /i "%%a"=="LOCAL_PORT"  set LOCAL_PORT=%%b
    if /i "%%a"=="ALLOWED_IPS" set ALLOWED_IPS=%%b
)

:: ── First-run wizard: prompt when ALLOWED_IPS is empty ────────────────────
if "%ALLOWED_IPS%"=="" (
    echo.
    echo ============================================================
    echo   Claude Cloak - Server Mode Setup
    echo ============================================================
    echo This VM will accept Claude Code traffic only from the IPs you
    echo whitelist below. Press Enter to skip optional sections.
    echo.

    set /p ALLOWED_IPS="Allowed IPs / CIDRs (comma-separated, e.g. 203.0.113.5,10.0.0.0/24): "
    if "!ALLOWED_IPS!"=="" (
        echo.
        echo   ERROR: ALLOWED_IPS cannot be empty in server mode.
        echo   Re-run start-server.bat and provide at least one IP / CIDR.
        echo.
        pause
        exit /b 1
    )

    set /p IP_LABELS="IP labels (optional, e.g. 203.0.113.5:phong,10.0.0.7:huy): "

    set USER_QUOTA_ENABLED=
    set /p USER_QUOTA_ENABLED="Enable per-user spend cap? (y/N): "
    if /i "!USER_QUOTA_ENABLED!"=="y" (
        set USER_QUOTA_ENABLED=true
        set USER_QUOTA_PERIOD=monthly
        set /p USER_QUOTA_PERIOD="  Period (monthly/daily) [monthly]: "
        if "!USER_QUOTA_PERIOD!"=="" set USER_QUOTA_PERIOD=monthly
        set USER_QUOTA_DEFAULT_USD=20.0
        set /p USER_QUOTA_DEFAULT_USD="  Default cap USD per user [20.0]: "
        if "!USER_QUOTA_DEFAULT_USD!"=="" set USER_QUOTA_DEFAULT_USD=20.0
        set /p USER_QUOTA_CAPS="  Per-label overrides (optional, e.g. phong:50,huy:30): "
    ) else (
        set USER_QUOTA_ENABLED=false
        set USER_QUOTA_PERIOD=monthly
        set USER_QUOTA_DEFAULT_USD=0
        set USER_QUOTA_CAPS=
    )

    echo.
    echo Writing config to .env...
    call :upsert_env DEPLOY_MODE server
    call :upsert_env ALLOWED_IPS "!ALLOWED_IPS!"
    call :upsert_env IP_LABELS "!IP_LABELS!"
    call :upsert_env USER_QUOTA_ENABLED "!USER_QUOTA_ENABLED!"
    call :upsert_env USER_QUOTA_PERIOD "!USER_QUOTA_PERIOD!"
    call :upsert_env USER_QUOTA_DEFAULT_USD "!USER_QUOTA_DEFAULT_USD!"
    call :upsert_env USER_QUOTA_CAPS "!USER_QUOTA_CAPS!"
    echo Done.
    echo.
)

:: ── Kill any stale process on the port ────────────────────────────────────
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :%LOCAL_PORT% ^| findstr LISTENING') do (
    taskkill /PID %%a /F >nul 2>&1
)

:: ── Auto-install dependencies if missing ──────────────────────────────────
python -c "import httpx" >nul 2>&1 || python -m pip install -r requirements.txt

echo Starting Claude Cloak in SERVER mode on port %LOCAL_PORT%...
echo Whitelisted: %ALLOWED_IPS%
echo.
echo The first request from a whitelisted device will auto-capture its
echo identity headers and lock them in .env for all other devices.
echo.
python proxy.py
pause
exit /b 0


:: ── Helper: upsert KEY=VALUE in .env (replace if present, else append) ────
:upsert_env
set "KEY=%~1"
set "VAL=%~2"
findstr /b /r /c:"^%KEY%=" .env >nul 2>&1
if errorlevel 1 (
    >>.env echo %KEY%=%VAL%
) else (
    powershell -NoProfile -Command "(Get-Content .env) -replace '^%KEY%=.*', '%KEY%=%VAL%' | Set-Content .env"
)
goto :eof
