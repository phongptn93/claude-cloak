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

:: Read LOCAL_PORT + TRANSPARENT_MODE from .env.
set LOCAL_PORT=
set TRANSPARENT_MODE=
for /f "usebackq tokens=1,2 delims==" %%a in (".env") do (
    if /i "%%a"=="LOCAL_PORT" set LOCAL_PORT=%%b
    if /i "%%a"=="TRANSPARENT_MODE" set TRANSPARENT_MODE=%%b
)
if /i "%TRANSPARENT_MODE%"=="true" (
    if "%LOCAL_PORT%"=="" set LOCAL_PORT=443
) else (
    if "%LOCAL_PORT%"=="" set LOCAL_PORT=9999
)

:: Kill process cu dang chiem port
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :%LOCAL_PORT% ^| findstr LISTENING') do (
    taskkill /PID %%a /F >nul 2>&1
)

:: Auto-install dependencies if missing
python -c "import httpx" >nul 2>&1 || python -m pip install -r requirements.txt

:: Auto-config Claude Code
if /i "%TRANSPARENT_MODE%"=="true" (
    echo.
    echo TRANSPARENT MODE ^(keeps Claude Code's Remote Control working^)
    python -c "import wsproto, websockets, cryptography" >nul 2>&1 || python -m pip install -r requirements.txt
    if not exist certs\api.anthropic.com.crt python gen_cert.py
    if not exist certs\ca.crt python gen_cert.py
    python setup_claude.py --transparent
    echo Reminder: add "127.0.0.1  api.anthropic.com" to
    echo   C:\Windows\System32\drivers\etc\hosts ^(edit as Administrator^),
    echo   and run this launcher as Administrator so it can bind port %LOCAL_PORT%.
    echo.
) else (
    python setup_claude.py
)

python proxy.py
pause
