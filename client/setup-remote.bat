@echo off
:: Claude Cloak - point Claude Code at a remote (shared VM) proxy.
::
:: Asks for the VM URL + your username. Writes them as
::   ANTHROPIC_BASE_URL=http://<vm>/u/<user>
:: into %USERPROFILE%\.claude\settings.json so the VM can attribute every
:: request to you on the dashboard / per-user quota.
::
:: Does NOT start a local proxy — Claude Code talks to the VM directly.

setlocal EnableDelayedExpansion
cd /d "%~dp0"

set REMOTE_URL=%~1
set CLOAK_USER=%~2

if "%REMOTE_URL%"=="" (
    set /p REMOTE_URL="VM proxy URL (e.g. http://10.0.0.5:9999): "
)
if "%REMOTE_URL%"=="" (
    echo.
    echo   ERROR: no URL provided.
    echo.
    pause
    exit /b 1
)

:: Strip trailing slash if present.
if "%REMOTE_URL:~-1%"=="/" set REMOTE_URL=%REMOTE_URL:~0,-1%

if "%CLOAK_USER%"=="" (
    set /p CLOAK_USER="Your username for the dashboard (e.g. phong) - blank to skip: "
)

set FULL_URL=%REMOTE_URL%
if not "%CLOAK_USER%"=="" set FULL_URL=%REMOTE_URL%/u/%CLOAK_USER%

python --version >nul 2>&1
if errorlevel 1 (
    echo   ERROR: Python is not installed or not on PATH.
    pause
    exit /b 1
)

uv run claude-cloak-setup --remote "%FULL_URL%"

echo.
if not "%CLOAK_USER%"=="" (
    echo You should appear as ^"%CLOAK_USER%^" on the VM dashboard.
    echo Verify any time with:
    echo   curl %FULL_URL%/whoami
)
echo.
pause
