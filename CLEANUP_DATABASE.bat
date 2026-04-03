@echo off
REM ============================================
REM Clean Up Old Database & Recreate Schema
REM ============================================

echo.
echo Stopping any running services...
echo.

REM Kill any Python processes on port 5000
netstat -ano | findstr :5000 >nul
if %errorlevel% equ 0 (
    echo Killing Flask backend on port 5000...
    for /f "tokens=5" %%a in ('netstat -ano ^| findstr :5000') do taskkill /PID %%a /F >nul 2>&1
)

REM Kill any Node processes on port 5173
netstat -ano | findstr :5173 >nul
if %errorlevel% equ 0 (
    echo Killing React frontend on port 5173...
    for /f "tokens=5" %%a in ('netstat -ano ^| findstr :5173') do taskkill /PID %%a /F >nul 2>&1
)

echo.
echo Waiting 2 seconds for processes to close...
timeout /t 2 /nobreak >nul

echo.
echo Removing old database file...
cd project\backend\instance

if exist ids.db (
    del ids.db
    echo ✓ Old database deleted
) else (
    echo ✓ No old database found
)

cd ..\..

echo.
echo ============================================
echo ✓ Cleanup complete!
echo.
echo The database will be recreated automatically
echo when you start the backend next time.
echo.
echo Next steps:
echo 1. START_BACKEND.bat (will create new schema)
echo 2. START_FRONTEND.bat
echo ============================================
echo.
pause
