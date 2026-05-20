@echo off
:: Claude Cloak - register Task Scheduler entry so the proxy auto-starts
:: at boot (no user login required) and re-runs if it crashes.
::
:: REQUIRES ADMINISTRATOR. Right-click this file -> Run as administrator.

setlocal
cd /d "%~dp0"
set TASK_NAME=ClaudeCloakServer
set RUN_SCRIPT=%~dp0service-run.bat

:: ── Admin check ───────────────────────────────────────────────────────────
net session >nul 2>&1
if errorlevel 1 (
    echo.
    echo   ERROR: This script must be run as Administrator.
    echo   Right-click install-service.bat -^> Run as administrator.
    echo.
    pause
    exit /b 1
)

:: ── Sanity check the proxy is already configured ─────────────────────────
if not exist .env (
    echo.
    echo   ERROR: .env not found. Run start-server.bat at least once to
    echo   configure ALLOWED_IPS / IP_LABELS / etc. before installing the
    echo   service.
    echo.
    pause
    exit /b 1
)
findstr /b /r /c:"^ALLOWED_IPS=." .env >nul 2>&1
if errorlevel 1 (
    echo.
    echo   ERROR: ALLOWED_IPS is empty in .env. Run start-server.bat to
    echo   configure it - the proxy refuses to start without a whitelist.
    echo.
    pause
    exit /b 1
)
if not exist "%RUN_SCRIPT%" (
    echo.
    echo   ERROR: service-run.bat is missing next to install-service.bat.
    echo.
    pause
    exit /b 1
)

:: ── Register the task (overwrites any existing one of the same name) ─────
echo Registering Scheduled Task "%TASK_NAME%"...
echo.
schtasks /create ^
    /tn "%TASK_NAME%" ^
    /tr "\"%RUN_SCRIPT%\"" ^
    /sc onstart ^
    /ru SYSTEM ^
    /rl HIGHEST ^
    /f

if errorlevel 1 (
    echo.
    echo   FAILED to create the task. Common causes:
    echo     - Not running as Administrator
    echo     - schtasks policy blocked
    echo.
    pause
    exit /b 1
)

:: Start it now so the user doesn't have to reboot to verify.
schtasks /run /tn "%TASK_NAME%" >nul 2>&1

echo.
echo ===============================================================
echo   Service installed.
echo ===============================================================
echo   Task name:   %TASK_NAME%
echo   Trigger:     At system startup (no login required)
echo   Account:     SYSTEM (full local privileges)
echo   Restart:     Automatic, 5s after each crash (loop in service-run.bat)
echo   Logs:        %~dp0service.log
echo.
echo   Useful commands:
echo     schtasks /query /tn %TASK_NAME%     - status
echo     schtasks /end   /tn %TASK_NAME%     - stop now
echo     schtasks /run   /tn %TASK_NAME%     - start now
echo     type service.log                     - view logs
echo     uninstall-service.bat                - remove the task
echo.
echo   Tail logs live (PowerShell):
echo     Get-Content service.log -Wait -Tail 50
echo.
pause
