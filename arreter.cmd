@echo off
rem Double-cliquer pour eteindre la plateforme et le relais d'IP reelle (Windows). Conteneurs et donnees conserves.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\stop.ps1"
echo.
pause
