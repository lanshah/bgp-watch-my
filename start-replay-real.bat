@echo off
rem Replays the committed sample of REAL RIS Live messages recorded by this tool (offline).
call "%~dp0_python.bat"
cd /d "%~dp0"
for /d %%D in (data\samples\*) do (
  %PY% -m bgpwatch demo --sample "%%D" --speed 60
  goto :done
)
echo No sample bundle found in data\samples.
:done
pause
