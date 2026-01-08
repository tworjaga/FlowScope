@echo off
echo ========================================
echo Network Analyzer Pro - Quick Start
echo ========================================
echo.

REM Change to script directory
cd /d "%~dp0"

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: This script must be run as Administrator!
    echo Right-click this file and select "Run as Administrator"
    echo.
    pause
    exit /b 1
)

echo [1/4] Checking Python installation...
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.10+ from https://www.python.org/
    pause
    exit /b 1
)

echo [2/4] Activating virtual environment...
if not exist "venv\" (
    echo Virtual environment not found. Creating...
    python -m venv venv
    if %errorLevel% neq 0 (
        echo ERROR: Failed to create virtual environment
        pause
        exit /b 1
    )
)

call venv\Scripts\activate.bat

echo [3/4] Checking dependencies...
pip show scapy >nul 2>&1
if %errorLevel% neq 0 (
    echo Installing dependencies...
    pip install -r requirements.txt
    if %errorLevel% neq 0 (
        echo ERROR: Failed to install dependencies
        pause
        exit /b 1
    )
)

echo [4/4] Starting Network Analyzer Pro...
echo.
echo ========================================
echo Application is starting...
echo Press Ctrl+C to stop
echo ========================================
echo.

python main.py

if %errorLevel% neq 0 (
    echo.
    echo ERROR: Application exited with error code %errorLevel%
    echo Check logs/analyzer.log for details
    pause
)
