@echo off
rem Replays the newest committed sample of REAL RIS Live messages recorded by this tool (offline).
rem Run 2 (14 Nov 2026) includes one real RPKI-invalid route; it plays in about one minute at 60x.
call "%~dp0_python.bat"
cd /d "%~dp0"
set "BUNDLE="
for /d %%D in (data\samples\*) do set "BUNDLE=%%D"
if not defined BUNDLE (
  echo No sample bundle found in data\samples.
  pause
  exit /b 1
)
%PY% -m bgpwatch demo --sample "%BUNDLE%" --speed 60
pause
