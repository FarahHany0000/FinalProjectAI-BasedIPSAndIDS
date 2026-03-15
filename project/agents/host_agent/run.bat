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

:: Create virtual environment if it doesn't exist
if not exist "%~dp0venv" (
    echo [1/3] Creating virtual environment...
    python -m venv "%~dp0venv"
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to create virtual environment.
        pause
        exit /b 1
    )
    echo       Virtual environment created.
) else (
    echo [1/3] Virtual environment already exists.
)

:: Activate virtual environment
call "%~dp0venv\Scripts\activate.bat"

:: Install dependencies inside venv
echo [2/3] Installing dependencies...
pip install -r "%~dp0requirements.txt" --quiet
if %errorlevel% neq 0 (
    echo [ERROR] Failed to install dependencies.
    pause
    exit /b 1
)

echo [3/3] Starting agent... (Press Ctrl+C to stop gracefully)
echo.

:: Run the agent (Ctrl+C will trigger graceful shutdown)
python "%~dp0host_agent.py" %*

:: Deactivate venv when agent exits
call deactivate 2>nul

:: If agent exits, pause so user sees the output
echo.
echo Agent stopped. Virtual environment is at: %~dp0venv
echo To delete agent from this device, just delete this entire folder.
pause
