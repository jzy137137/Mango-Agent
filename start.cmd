@echo off
setlocal
cd /d "%~dp0"
set PYTHONDONTWRITEBYTECODE=1
set PYTHONUTF8=1
set "PY=C:\Users\hp\Documents\Codex\2026-11-03\new-chat\work\mango-pyenv\Scripts\python.exe"
if not exist "%PY%" (
  echo Python executable not found. Please check the path in start.cmd.
  pause
  exit /b 1
)
"%PY%" -X utf8 "%~dp0launcher.py"
if errorlevel 1 pause
endlocal
