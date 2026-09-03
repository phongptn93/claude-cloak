@echo off
echo === Cai dat AI Proxy ===
cd /d "%~dp0.."
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
echo.
echo === Cai xong! Chay setup.bat de tao config ===
pause
