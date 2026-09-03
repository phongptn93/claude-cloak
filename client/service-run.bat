@echo off
:: Claude Cloak - service wrapper. Loops the proxy with crash recovery and
:: appends all output to service.log. Invoked by Task Scheduler (registered
:: by install-service.bat) so the proxy survives both reboots and crashes.
::
:: To run manually for testing:   service-run.bat

cd /d "%~dp0"
set DEPLOY_MODE=server

:: uv is installed per-user by default, so the SYSTEM account may not see it
:: on PATH. Try PATH first, then the two standard install locations.
set "UVBIN=uv"
where uv >nul 2>&1
if errorlevel 1 (
    if exist "%USERPROFILE%\.local\bin\uv.exe" set "UVBIN=%USERPROFILE%\.local\bin\uv.exe"
    if exist "%LOCALAPPDATA%\Programs\uv\uv.exe" set "UVBIN=%LOCALAPPDATA%\Programs\uv\uv.exe"
)

:loop
>> service.log echo.
>> service.log echo === [%date% %time%] Starting Claude Cloak proxy ===
"%UVBIN%" run claude-cloak >> service.log 2>&1
>> service.log echo === [%date% %time%] Exited code %ERRORLEVEL% - restarting in 5s ===
timeout /t 5 /nobreak >nul
goto loop
