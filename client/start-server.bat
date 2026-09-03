@echo off
:: Claude Cloak - server-mode launcher for a shared VM (Windows).
::
:: Interactive setup the first time it runs: prompts for ALLOWED_IPS, optional
:: IP_LABELS, per-user spend caps, identity-lock IP, and stats privacy.
:: Re-run the wizard later with:
::    start-server.bat --reconfigure
::
:: After the first /v1/messages request from a whitelisted device, the proxy
:: auto-captures that device's identity headers and locks them in .env for
:: every other device.

setlocal EnableDelayedExpansion
cd /d "%~dp0"

set FORCE_WIZARD=0
if /i "%~1"=="--reconfigure" set FORCE_WIZARD=1
if /i "%~1"=="--reconfig"    set FORCE_WIZARD=1
if /i "%~1"=="-r"            set FORCE_WIZARD=1

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

:: ── Read existing values from .env ────────────────────────────────────────
set LOCAL_PORT=9999
set ALLOWED_IPS=
set IP_LABELS=
set USER_QUOTA_ENABLED=
set USER_QUOTA_PERIOD=
set USER_QUOTA_DEFAULT_USD=
set USER_QUOTA_CAPS=
set CAPTURE_LOCK_FROM_IP=
set STATS_PRIVATE=
for /f "usebackq tokens=1,* delims==" %%a in (".env") do (
    if /i "%%a"=="LOCAL_PORT"              set LOCAL_PORT=%%b
    if /i "%%a"=="ALLOWED_IPS"             set ALLOWED_IPS=%%b
    if /i "%%a"=="IP_LABELS"               set IP_LABELS=%%b
    if /i "%%a"=="USER_QUOTA_ENABLED"      set USER_QUOTA_ENABLED=%%b
    if /i "%%a"=="USER_QUOTA_PERIOD"       set USER_QUOTA_PERIOD=%%b
    if /i "%%a"=="USER_QUOTA_DEFAULT_USD"  set USER_QUOTA_DEFAULT_USD=%%b
    if /i "%%a"=="USER_QUOTA_CAPS"         set USER_QUOTA_CAPS=%%b
    if /i "%%a"=="CAPTURE_LOCK_FROM_IP"    set CAPTURE_LOCK_FROM_IP=%%b
    if /i "%%a"=="STATS_PRIVATE"           set STATS_PRIVATE=%%b
)

:: ── Decide whether to run the wizard ──────────────────────────────────────
set RUN_WIZARD=0
if "%ALLOWED_IPS%"==""    set RUN_WIZARD=1
if "%FORCE_WIZARD%"=="1"  set RUN_WIZARD=1
if "%RUN_WIZARD%"=="0"    goto :after_wizard

:: ── Wizard (goto-based, NOT inside an if-block, so parens are safe) ───────
echo.
echo ============================================================
echo   Claude Cloak - Server Mode Setup
if "%FORCE_WIZARD%"=="1" echo   ^(reconfigure - press Enter to keep current value^)
echo ============================================================
echo.

call :prompt_default "Allowed IPs / CIDRs (e.g. 203.0.113.5,10.0.0.0/24)" "%ALLOWED_IPS%" ALLOWED_IPS
if "%ALLOWED_IPS%"=="" (
    echo.
    echo   ERROR: ALLOWED_IPS cannot be empty in server mode.
    echo.
    pause
    exit /b 1
)

call :prompt_default "IP labels (optional, e.g. 203.0.113.5:phong)" "%IP_LABELS%" IP_LABELS

set UQ_DEFAULT=N
if /i "%USER_QUOTA_ENABLED%"=="true" set UQ_DEFAULT=Y
call :prompt_default "Enable per-user spend cap? (y/N)" "%UQ_DEFAULT%" ENABLE_UQ

if /i "%ENABLE_UQ%"=="Y" goto :wizard_has_quota
if /i "%ENABLE_UQ%"=="YES" goto :wizard_has_quota
set USER_QUOTA_ENABLED=false
set USER_QUOTA_PERIOD=monthly
set USER_QUOTA_DEFAULT_USD=0
set USER_QUOTA_CAPS=
goto :wizard_hardening

:wizard_has_quota
set USER_QUOTA_ENABLED=true
if "%USER_QUOTA_PERIOD%"==""      set USER_QUOTA_PERIOD=monthly
if "%USER_QUOTA_DEFAULT_USD%"=="" set USER_QUOTA_DEFAULT_USD=20.0
call :prompt_default "  Period (monthly/daily)"               "%USER_QUOTA_PERIOD%"      USER_QUOTA_PERIOD
call :prompt_default "  Default cap USD per user"             "%USER_QUOTA_DEFAULT_USD%" USER_QUOTA_DEFAULT_USD
call :prompt_default "  Per-label overrides (e.g. phong:50)"  "%USER_QUOTA_CAPS%"        USER_QUOTA_CAPS

:wizard_hardening
echo.
echo -- Hardening [optional] -----------------------------------
call :prompt_default "Restrict identity capture to one IP (blank = any whitelisted)" "%CAPTURE_LOCK_FROM_IP%" CAPTURE_LOCK_FROM_IP

set SP_DEFAULT=N
if /i "%STATS_PRIVATE%"=="true" set SP_DEFAULT=Y
call :prompt_default "Make dashboard/quota private to admin (loopback only)? (y/N)" "%SP_DEFAULT%" ENABLE_SP
set STATS_PRIVATE=false
if /i "%ENABLE_SP%"=="Y"   set STATS_PRIVATE=true
if /i "%ENABLE_SP%"=="YES" set STATS_PRIVATE=true

echo.
echo Writing config to .env...
call :upsert_env DEPLOY_MODE              server
call :upsert_env ALLOWED_IPS              "%ALLOWED_IPS%"
call :upsert_env IP_LABELS                "%IP_LABELS%"
call :upsert_env USER_QUOTA_ENABLED       "%USER_QUOTA_ENABLED%"
call :upsert_env USER_QUOTA_PERIOD        "%USER_QUOTA_PERIOD%"
call :upsert_env USER_QUOTA_DEFAULT_USD   "%USER_QUOTA_DEFAULT_USD%"
call :upsert_env USER_QUOTA_CAPS          "%USER_QUOTA_CAPS%"
call :upsert_env CAPTURE_LOCK_FROM_IP     "%CAPTURE_LOCK_FROM_IP%"
call :upsert_env STATS_PRIVATE            "%STATS_PRIVATE%"
echo Done.
echo.

:after_wizard

:: ── Kill any stale process on the port ────────────────────────────────────
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :%LOCAL_PORT% ^| findstr LISTENING') do (
    taskkill /PID %%a /F >nul 2>&1
)

:: ── Ensure uv is available ────────────────────────────────────────────────
where uv >nul 2>&1
if errorlevel 1 (
    echo uv not found - installing from https://astral.sh/uv ...
    powershell -ExecutionPolicy Bypass -c "irm https://astral.sh/uv/install.ps1 | iex"
    set "PATH=%USERPROFILE%\.local\bin;%PATH%"
)
where uv >nul 2>&1
if errorlevel 1 (
    echo uv install failed. See https://docs.astral.sh/uv/getting-started/installation/
    pause
    exit /b 1
)
uv sync --quiet

echo Starting Claude Cloak in SERVER mode on port %LOCAL_PORT%...
echo Whitelisted: %ALLOWED_IPS%
if not "%CAPTURE_LOCK_FROM_IP%"=="" echo Identity will be locked from IP: %CAPTURE_LOCK_FROM_IP%
echo.
uv run claude-cloak
pause
exit /b 0


:: ──────────────────────────────────────────────────────────────────────────
:: Subroutines (each ends with `goto :eof` and runs in its own scope thanks
:: to setlocal/endlocal — no nested-paren parsing surprises).
:: ──────────────────────────────────────────────────────────────────────────

:prompt_default
:: %~1 = prompt label, %~2 = default value, %~3 = name of variable to set
setlocal EnableDelayedExpansion
set "ANSWER="
if "%~2"=="" (
    set /p "ANSWER=%~1: "
) else (
    set /p "ANSWER=%~1 [%~2]: "
    if "!ANSWER!"=="" set "ANSWER=%~2"
)
endlocal & set "%~3=%ANSWER%"
goto :eof


:upsert_env
:: %~1 = key, %~2 = value — replace if present, else append.
set "KEY=%~1"
set "VAL=%~2"
findstr /b /r /c:"^%KEY%=" .env >nul 2>&1
if errorlevel 1 (
    >>.env echo %KEY%=%VAL%
    goto :eof
)
powershell -NoProfile -ExecutionPolicy Bypass -Command "(Get-Content .env) -replace '^%KEY%=.*', '%KEY%=%VAL%' | Set-Content .env"
goto :eof
