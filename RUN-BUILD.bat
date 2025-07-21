@echo off
setlocal enabledelayedexpansion
title Build and Run Production Network Management Platform

SET "FRONTEND_DIST_DIR=frontend\dist"
SET "BACKEND_PORT=5000"
SET "FRONTEND_PORT=8000"

echo ================================================================
echo.
echo   Building and Running Production Network Management Platform...
echo.
echo ================================================================

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH!
    echo Please install Python and try again.
    pause
    exit /b 1
)

REM Check if Node.js is available for frontend build
node --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Node.js is not installed or not in PATH!
    echo Node.js is required to build the frontend.
    echo Please install Node.js and try again.
    pause
    exit /b 1
)

REM Check if frontend exists
if not exist "frontend\package.json" (
    echo ERROR: Frontend project not found!
    echo Please ensure frontend folder exists with package.json.
    pause
    exit /b 1
)

REM Check if backend exists
if not exist "backend\server.py" (
    echo ERROR: Backend server not found!
    echo Please ensure backend\server.py exists.
    pause
    exit /b 1
)

REM --- Check if already built and prompt user ---
if exist "%FRONTEND_DIST_DIR%\index.html" (
    echo.
    echo A previous build was detected in '%FRONTEND_DIST_DIR%'.
    echo.
    echo Please choose an option:
    echo   1. Rebuild the application
    echo   2. Start the existing build
    echo.

    CHOICE /C 12 /M "Enter your choice (1 or 2)"

    if errorlevel 2 (
        goto :RUN_APP
    ) else if errorlevel 1 (
        goto :BUILD_APP
    ) else (
        echo An unexpected error occurred with your input. Exiting.
        pause
        exit /b 1
    )
)

:BUILD_APP
echo.
echo Building production frontend...
echo.

REM Install frontend dependencies if needed
if not exist "frontend\node_modules" (
    echo Installing frontend dependencies...
    cd frontend
    call npm install
    if errorlevel 1 (
        echo ERROR: Failed to install frontend dependencies!
        pause
        exit /b 1
    )
    cd ..
    echo Frontend dependencies installed successfully!
    echo.
)

REM Build frontend for production
echo Building frontend for production...
cd frontend
call npm run build
if errorlevel 1 (
    echo ERROR: Frontend build failed!
    pause
    exit /b 1
)
cd ..

REM Install backend dependencies if needed
echo.
echo Checking backend dependencies...
if not exist "backend\venv" (
    echo Creating Python virtual environment...
    cd backend
    python -m venv venv
    call venv\Scripts\activate.bat
    pip install -r requirements.txt
    if errorlevel 1 (
        echo ERROR: Failed to install backend dependencies!
        pause
        exit /b 1
    )
    cd ..
    echo Backend dependencies installed successfully!
    echo.
)

echo.
echo ================================================================
echo   Build Complete!
echo.
echo   Frontend built successfully: %FRONTEND_DIST_DIR%
echo   Backend ready: backend\server.py
echo.
echo ================================================================
echo.

:RUN_APP
echo.
echo ================================================================
echo   Starting Production Network Management Platform...
echo ================================================================
echo.

REM Create output directories if they don't exist
if not exist "output" (
    mkdir output
    echo Created output directory
)

REM Check if commands.yaml exists, create if not
if not exist "backend\commands.yaml" (
    echo Creating default commands.yaml configuration...
    echo arista_eos: > "backend\commands.yaml"
    echo   mac_address_table: >> "backend\commands.yaml"
    echo     - show mac address-table >> "backend\commands.yaml"
    echo   ip_arp: >> "backend\commands.yaml"
    echo     - show ip arp >> "backend\commands.yaml"
    echo   interfaces_status: >> "backend\commands.yaml"
    echo     - show interfaces status >> "backend\commands.yaml"
    echo   mlag_interfaces: >> "backend\commands.yaml"
    echo     - show mlag interfaces detail >> "backend\commands.yaml"
    echo   system_info: >> "backend\commands.yaml"
    echo     - show version >> "backend\commands.yaml"
    echo     - show hostname >> "backend\commands.yaml"
    echo     - show inventory >> "backend\commands.yaml"
    echo Default commands.yaml created!
    echo.
)

REM Start the backend server
echo Starting backend server on http://127.0.0.1:%BACKEND_PORT%...
START "Backend (Production Flask)" cmd /c "cd backend && echo Starting Production Flask Server... && echo. && venv\Scripts\python.exe server.py && echo. && echo Backend server stopped. && pause"

REM Wait for backend to start
echo Waiting for backend to initialize...
timeout /t 8 /nobreak >nul

REM Start frontend server
echo.
echo Starting frontend server on http://localhost:%FRONTEND_PORT%...
echo Serving production build from "%FRONTEND_DIST_DIR%"
echo.
echo ================================================================
echo   Production Environment Started!
echo.
echo   Frontend: http://localhost:%FRONTEND_PORT%
echo   Backend:  http://127.0.0.1:%BACKEND_PORT%
echo.
echo   To stop servers:
echo   - Close the Backend window or press Ctrl+C
echo   - Close this window to stop frontend
echo.
echo ================================================================
echo.

REM Open browser
echo Opening http://localhost:%FRONTEND_PORT% in your browser...
start "" "http://localhost:%FRONTEND_PORT%"

REM Serve frontend using Python HTTP server
cd /d "%FRONTEND_DIST_DIR%"
echo Production frontend server starting...
python -m http.server %FRONTEND_PORT%

REM Return to original directory
cd /d "%~dp0"

echo.
echo Production servers stopped.
pause