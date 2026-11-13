@echo off
rem Offline demo: replays the labelled SYNTHETIC incident set with the dashboard (no internet needed).
call "%~dp0_python.bat"
cd /d "%~dp0"
%PY% -m bgpwatch demo --speed 120
pause
