@echo off
title Host IDS Agent
echo ============================================
echo   Host IDS Agent - Setup and Run
echo ============================================
echo.

:: Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH.
    echo Download from: https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during install.
    pause
    exit /b 1
)

:: Install dependencies
echo [1/2] Installing dependencies...
pip install -r "%~dp0requirements.txt" --quiet
if %errorlevel% neq 0 (
    echo [ERROR] Failed to install dependencies.
    pause
    exit /b 1
)

echo [2/2] Starting agent...
echo.

:: Run the agent
python "%~dp0host_agent.py" %*

:: If agent exits, pause so user sees the error
echo.
echo Agent stopped.
pause
