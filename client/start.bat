@echo off
cd /d "%~dp0"

:: Tao .env neu chua co
if not exist .env (
    copy .env.example .env >nul 2>&1
    if not exist .env echo LOCAL_PORT=9999> .env
)

:: Kill process cu dang chiem port
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :9999 ^| findstr LISTENING') do (
    taskkill /PID %%a /F >nul 2>&1
)

:: Auto-install dependencies if missing
python -c "import httpx" >nul 2>&1 || pip install -r requirements.txt

:: Auto-config Claude Code proxy URL
python setup_claude.py

python proxy.py
pause
