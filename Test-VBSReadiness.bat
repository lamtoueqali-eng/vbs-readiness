@echo off
rem VBS Readiness - self-test: creates a temporary fake environment (scripts, Outlook add-ins, macros, PST), scans it, then deletes it.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0VBSReadiness.ps1" -SelfTest
echo.
pause
