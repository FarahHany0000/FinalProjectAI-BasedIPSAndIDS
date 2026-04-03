@echo off
REM ============================================
REM System Health Check
REM ============================================

echo.
echo ============================================
echo  AI IDS/IPS System Health Check
echo ============================================
echo.

REM Check Python
echo [1/6] Checking Python...
python --version >nul 2>&1
if %errorlevel% equ 0 (
    echo  ✓ Python installed
    python --version
) else (
    echo  ✗ Python NOT installed or not in PATH
    echo    Install from: https://www.python.org
    goto :error
)
echo.

REM Check Node.js
echo [2/6] Checking Node.js...
node --version >nul 2>&1
if %errorlevel% equ 0 (
    echo  ✓ Node.js installed
    node --version
) else (
    echo  ✗ Node.js NOT installed or not in PATH
    echo    Install from: https://nodejs.org
    goto :error
)
echo.

REM Check npm
echo [3/6] Checking npm...
npm --version >nul 2>&1
if %errorlevel% equ 0 (
    echo  ✓ npm installed
    npm --version
) else (
    echo  ✗ npm NOT installed or not in PATH
    goto :error
)
echo.

REM Check Npcap
echo [4/6] Checking Npcap (for network capture)...
wmic product list | findstr /i "Npcap" >nul 2>&1
if %errorlevel% equ 0 (
    echo  ✓ Npcap installed
) else (
    echo  ⚠ Npcap NOT installed
    echo    Download from: https://npcap.com
    echo    (Optional - network sensor will still work for testing)
)
echo.

REM Check Flask
echo [5/6] Checking Flask (backend framework)...
python -c "import flask" >nul 2>&1
if %errorlevel% equ 0 (
    echo  ✓ Flask installed
) else (
    echo  ✗ Flask NOT installed
    echo    Run: cd project\backend ^&^& pip install -r requirements.txt
    goto :error
)
echo.

REM Check network interface
echo [6/6] Checking network interface for VMware...
ipconfig | findstr /i "Ethernet.*VMware\|VMnet1" >nul 2>&1
if %errorlevel% equ 0 (
    echo  ✓ VMware network adapter found
    ipconfig /all | findstr /A 5 "VMnet1" | findstr "IPv4"
) else (
    echo  ⚠ VMware network adapter NOT found
    echo    Run: ipconfig /all
    echo    Look for "VMware Network Adapter VMnet1"
)
echo.

REM Summary
echo ============================================
echo  ✓ System appears ready!
echo.
echo  Next steps:
echo    1. Open 2 command prompts
echo    2. In prompt 1: START_BACKEND.bat
echo    3. Wait 5 seconds
echo    4. In prompt 2: START_FRONTEND.bat
echo    5. Open browser: http://localhost:5173
echo.
echo  For detailed guide, see: RUN_FULL_SYSTEM.md
echo ============================================
echo.
pause
goto :end

:error
echo.
echo ============================================
echo  ✗ Setup incomplete!
echo  Please install missing components above.
echo ============================================
echo.
pause

:end
