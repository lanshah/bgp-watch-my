@echo off
rem Finds the project's virtual-environment Python, creating it on first use.
if not exist "%~dp0.venv\Scripts\python.exe" (
  echo Creating virtual environment ...
  py -3 -m venv "%~dp0.venv" || python -m venv "%~dp0.venv"
  "%~dp0.venv\Scripts\python.exe" -m pip install -q -r "%~dp0requirements.txt"
)
set PY="%~dp0.venv\Scripts\python.exe"
