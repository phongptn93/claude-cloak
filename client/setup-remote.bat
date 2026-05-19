@echo off
:: Claude Cloak - point Claude Code at a remote (shared VM) proxy.
::
:: Usage:
::   setup-remote.bat                          (prompts for URL)
::   setup-remote.bat http://10.0.0.5:9999     (uses given URL)
::
:: Writes ANTHROPIC_BASE_URL=<URL> into %USERPROFILE%\.claude\settings.json
:: so Claude Code routes through the VM. Does NOT start a local proxy.

cd /d "%~dp0"

set REMOTE_URL=%~1
if "%REMOTE_URL%"=="" (
    set /p REMOTE_URL="Enter remote proxy URL (e.g. http://10.0.0.5:9999): "
)

if "%REMOTE_URL%"=="" (
    echo.
    echo   ERROR: no URL provided.
    echo   Example: setup-remote.bat http://10.0.0.5:9999
    echo.
    pause
    exit /b 1
)

:: Auto-install Python deps if needed (setup_claude.py is stdlib-only,
:: but keeping parity with start.bat in case requirements grow).
python --version >nul 2>&1
if errorlevel 1 (
    echo   ERROR: Python is not installed or not on PATH.
    pause
    exit /b 1
)

python setup_claude.py --remote "%REMOTE_URL%"
pause
