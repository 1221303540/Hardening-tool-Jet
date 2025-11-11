@echo off
REM Database Security Scanner - GUI Launcher
REM Windows batch file to launch the GUI application

echo ========================================
echo Database Security Scanner
echo ========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH
    echo Please install Python 3.8 or higher from https://www.python.org/
    pause
    exit /b 1
)

echo Launching GUI application...
echo.

REM Launch the GUI application
pythonw gui_app.py

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Failed to launch the application
    echo Try running: python gui_app.py
    pause
    exit /b 1
)

exit /b 0

