@echo off
:: Claude Cloak - service wrapper. Loops proxy.py with crash recovery and
:: appends all output to service.log. Invoked by Task Scheduler (registered
:: by install-service.bat) so the proxy survives both reboots and crashes.
::
:: To run manually for testing:   service-run.bat

cd /d "%~dp0"
set DEPLOY_MODE=server

:: Prefer the `py` launcher: when Python is installed with the official
:: installer's "Install launcher for all users" checkbox, py.exe lands in
:: C:\Windows, which is ALWAYS in the SYSTEM account's PATH. Fall back to
:: `python` from PATH if the launcher isn't installed.
where py >nul 2>&1
if not errorlevel 1 (
    set PYBIN=py
) else (
    set PYBIN=python
)

:loop
>> service.log echo.
>> service.log echo === [%date% %time%] Starting Claude Cloak proxy ===
%PYBIN% proxy.py >> service.log 2>&1
>> service.log echo === [%date% %time%] Exited code %ERRORLEVEL% - restarting in 5s ===
timeout /t 5 /nobreak >nul
goto loop
