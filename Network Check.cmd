@echo off
rem One-shot read-only check. Keep this launcher beside network-check.ps1.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0network-check.ps1" -Interactive
if errorlevel 1 pause
