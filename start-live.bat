@echo off
rem Live monitoring. First run builds the watch list and baseline from RIPEstat/PeeringDB (needs internet).
call "%~dp0_python.bat"
cd /d "%~dp0"
if not exist data\baseline.json %PY% -m bgpwatch setup
%PY% -m bgpwatch live --record --open
pause
