@echo off
call "%~dp0_python.bat"
cd /d "%~dp0"
%PY% -m pytest -q && %PY% -m bgpwatch evaluate --strict
pause
