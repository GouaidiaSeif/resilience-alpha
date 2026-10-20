@echo off
rem Double-cliquer pour lancer toute la plateforme (Windows). Equivaut a : scripts\start.ps1
rem Prerequis : Docker Desktop et Python 3.10+ installes.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\start.ps1"
echo.
pause
