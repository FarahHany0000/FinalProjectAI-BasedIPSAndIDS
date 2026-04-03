@echo off
REM ============================================
REM Start AI IDS/IPS Backend Server
REM ============================================

echo.
echo ============================================
echo  Starting Backend (Flask) on :5000
echo ============================================
echo.

cd project\backend
python -m flask --app app run

REM If Flask closes, show error
echo.
echo ERROR: Backend crashed!
echo Check that Python 3.10+ is installed
echo Try: python --version
pause
