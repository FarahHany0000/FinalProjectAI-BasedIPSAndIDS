@echo off
REM ============================================
REM Start AI IDS/IPS Frontend Server
REM ============================================

echo.
echo ============================================
echo  Starting Frontend (React) on :5173
echo ============================================
echo.

cd project\frontend

REM Check if node_modules exists
if not exist node_modules (
    echo Installing dependencies...
    echo.
    call npm install
    echo.
)

REM Start dev server
call npm run dev

REM If npm closes, show error
echo.
echo ERROR: Frontend crashed!
echo Check that Node.js 18+ is installed
echo Try: node --version
pause
