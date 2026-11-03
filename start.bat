@echo off
rem Double-click to start. First run creates .venv and installs requirements.
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo [setup] creating .venv ...
  python -m venv .venv || goto :fail
  ".venv\Scripts\python.exe" -m pip install -q -r requirements.txt || goto :fail
)
start "" "http://127.0.0.1:5050"
".venv\Scripts\python.exe" run.py
goto :eof

:fail
echo [error] setup failed. Install Python 3.11+ and try again.
pause
