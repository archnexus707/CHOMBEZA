@echo off
title CHOMBEZA Bug Bounty Pro Installer
echo =========================================
echo   CHOMBEZA BUG BOUNTY PRO
echo   Installation Script
echo =========================================
echo.

REM Check Python version
echo Checking Python version...
python --version >nul 2>&1
if errorlevel 1 (
    echo Python not found! Please install Python 3.7+
    pause
    exit /b 1
)

for /f "tokens=*" %%i in ('python --version') do set pyver=%%i
echo %pyver% detected
echo.

REM Create virtual environment
echo Creating virtual environment...
python -m venv venv
call venv\Scripts\activate.bat

REM Upgrade pip
echo Upgrading pip...
python -m pip install --upgrade pip

REM Install requirements
echo Installing requirements...
pip install -r requirements.txt

REM Check if installation was successful
if %errorlevel% equ 0 (
    echo.
    echo =========================================
    echo ✅ CHOMBEZA Installation Complete!
    echo =========================================
    echo.
    echo To activate the environment:
    echo   venv\Scripts\activate
    echo.
    echo To start CHOMBEZA GUI:
    echo   python main.py
    echo.
    echo To use CHOMBEZA CLI:
    echo   python main.py https://target.com --scan-type quick
    echo.
    echo Happy Hunting! 🐞
) else (
    echo.
    echo ❌ Installation failed! Check errors above.
)

pause