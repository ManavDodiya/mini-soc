@echo off
echo.
echo ╔══════════════════════════════════════════════╗
echo ║      Mini SOC Platform — Setup ^& Launch      ║
echo ╚══════════════════════════════════════════════╝
echo.

where python >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Python not found. Install from https://python.org
    pause
    exit /b 1
)

if not exist .venv (
    echo Creating virtual environment...
    python -m venv .venv
)

call .venv\Scripts\activate.bat
echo Virtual environment active.

echo Installing dependencies...
pip install -q -r requirements.txt

echo.
echo Starting Mini SOC Platform...
echo Open browser: http://127.0.0.1:5000
echo Press Ctrl+C to stop.
echo.

python app.py
pause
