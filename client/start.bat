@echo off
:: Claude Cloak - LOCAL mode launcher (Windows).
::
:: Runs a single-machine proxy at 127.0.0.1:9999 and auto-configures Claude
:: Code to use it. For a shared VM deployment use start-server.bat instead,
:: and on the clients use setup-remote.bat (no local proxy needed).

cd /d "%~dp0"

echo ============================================================
echo   Claude Cloak - LOCAL MODE
echo   Runs a per-device proxy on 127.0.0.1:9999.
echo   For a shared VM:
echo     - on the VM:     start-server.bat
echo     - on each user:  setup-remote.bat http://VM:9999 ^<username^>
echo ============================================================
echo.

:: Tao .env neu chua co
if not exist .env (
    copy .env.example .env >nul 2>&1
    if not exist .env echo LOCAL_PORT=9999> .env
)

:: Force local mode for this process so a leftover DEPLOY_MODE=server in
:: .env can't accidentally bind 0.0.0.0 from start.bat.
set DEPLOY_MODE=local

:: Read LOCAL_PORT from .env (default 9999) so the kill below targets the
:: right port if the user customised it.
set LOCAL_PORT=9999
for /f "usebackq tokens=1,2 delims==" %%a in (".env") do (
    if /i "%%a"=="LOCAL_PORT" set LOCAL_PORT=%%b
)

:: Kill process cu dang chiem port
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :%LOCAL_PORT% ^| findstr LISTENING') do (
    taskkill /PID %%a /F >nul 2>&1
)

:: Auto-install dependencies if missing
python -c "import httpx" >nul 2>&1 || python -m pip install -r requirements.txt

:: Auto-config Claude Code proxy URL (local)
python setup_claude.py

python proxy.py
pause
