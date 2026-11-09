@echo off
chcp 65001 >nul
cd /d "%~dp0"
set PYTHONDONTWRITEBYTECODE=1
"C:\Users\hp\Documents\Codex\2026-11-03\new-chat\work\mango-pyenv\Scripts\python.exe" setup_model.py
if errorlevel 1 pause
