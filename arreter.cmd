@echo off
rem Double-cliquer pour arreter la plateforme et le relais d'IP reelle (Windows). Donnees conservees.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\stop.ps1"
echo.
pause
