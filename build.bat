@echo off
rem resiproxy — Windows. Same stages as build.sh.
setlocal
cd /d "%~dp0"
set PY=python

echo == install ==
%PY% -m pip install -r requirements.txt 2>nul || echo   (aiohttp already present - continuing)

echo == compile check ==
%PY% -m compileall -q tooling recon enum vuln exploit egress ui run.py >nul && echo   all modules compile

echo == setup ==
%PY% run.py setup

echo.
echo == pipeline ==
%PY% run.py pipeline %*

echo.
echo next:
echo   %PY% run.py serve --grade B
echo   %PY% run.py chrome
echo   %PY% run.py ui
endlocal
