@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if errorlevel 1 (
  echo Python launcher ^(py^) not found. Install Python 3.11+ and try again.
  pause
  exit /b 1
)
echo ================================================
echo        COMPESA EVENT INTELLIGENCE PLATFORM
echo ================================================
if not exist .venv\Scripts\python.exe py -m venv .venv
set PY=.venv\Scripts\python.exe
echo Installing / checking dependencies...
%PY% -m pip install --disable-pip-version-check -q -r requirements.txt
if errorlevel 1 (
  echo Dependency installation failed.
  pause
  exit /b 1
)
echo.
echo COMPESA is starting...
echo Open: http://127.0.0.1:8000
echo.
%PY% -m uvicorn app:app --host 127.0.0.1 --port 8000
pause
