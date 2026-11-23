@echo off
rem VBS Readiness - read-only scan. Right-click > "Run as administrator" for the full check.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0VBSReadiness.ps1" %*
echo.
pause
