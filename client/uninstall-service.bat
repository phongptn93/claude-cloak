@echo off
:: Claude Cloak - remove the auto-start Scheduled Task.
::
:: REQUIRES ADMINISTRATOR.

setlocal
set TASK_NAME=ClaudeCloakServer

net session >nul 2>&1
if errorlevel 1 (
    echo.
    echo   ERROR: must be run as Administrator.
    echo.
    pause
    exit /b 1
)

echo Stopping "%TASK_NAME%"...
schtasks /end /tn "%TASK_NAME%" >nul 2>&1

echo Removing scheduled task...
schtasks /delete /tn "%TASK_NAME%" /f

if errorlevel 1 (
    echo Task '%TASK_NAME%' did not exist or could not be removed.
) else (
    echo.
    echo Removed. The proxy will no longer auto-start at boot.
    echo The .env / .quota.json files are untouched.
)
pause
