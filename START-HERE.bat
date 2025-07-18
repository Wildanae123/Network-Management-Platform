@REM START-HERE.bat
@echo off
title Network Data App - Development Environment

echo ================================================================
echo.
echo   Network Data App v2.2.0
echo   Starting Development Environment...
echo.
echo ================================================================

REM Check if backend virtual environment exists
if not exist "backend\venv\Scripts\python.exe" (
    echo ERROR: Backend virtual environment not found!
    echo.
    echo Please run INSTALL.bat first to set up the environment.
    echo.
    pause
    exit /b 1
)

REM Check if backend server exists
if not exist "backend\server.py" (
    echo ERROR: backend\server.py not found!
    echo.
    echo Please ensure server.py is in the backend folder.
    echo.
    pause
    exit /b 1
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

REM Create output directory if it doesn't exist
if not exist "output" (
    mkdir output
    echo Created output directory
    echo.
)

REM Create uploads directory if it doesn't exist
if not exist "uploads" (
    mkdir uploads
    echo Created uploads directory
    echo.
)

REM Check if frontend node_modules exists
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

REM Check if App component exists
if not exist "frontend\src\App.jsx" (
    echo ERROR: App.jsx not found in frontend\src\
    echo.
    pause
    exit /b 1
) else (
    echo App component found!
    if not exist "frontend\src\App.css" (
        echo WARNING: App.css not found
    ) else (
        echo App.css found!
    )
    echo.
)

echo ================================================================
echo   Starting Development Servers...
echo ================================================================
echo.

echo Starting Backend Development Server...
START "Backend (Flask API)" cmd /c "cd backend && echo Starting Flask Development Server on http://127.0.0.1:5000... && echo. && venv\Scripts\python.exe server.py && echo. && echo Backend server stopped. && pause"

REM Wait for backend to start
echo Waiting for backend to initialize...
timeout /t 8 /nobreak >nul

echo Starting Frontend Development Server...
START "Frontend (React + Vite)" cmd /c "cd frontend && echo Starting Vite Development Server on http://localhost:3000... && echo. && npm run dev && echo. && echo Frontend server stopped. && pause"

REM Wait for frontend to start
echo Waiting for frontend to initialize...
timeout /t 10 /nobreak >nul

echo.
echo ================================================================
echo   Development Environment Started Successfully!
echo.
echo   Frontend URL: http://localhost:3000
echo   Backend API:  http://127.0.0.1:5000
echo.
echo   Quick Start Guide:
echo   1. Open http://localhost:3000 in your browser
echo   2. Upload your CSV file with device information
echo   3. Enter your API credentials (username/password)
echo   4. Select commands to execute
echo   5. Click "Start API Collection"
echo   6. Monitor real-time progress
echo   7. Export results when complete
echo.
echo   CSV Format Required:
echo   - IP MGMT (device IP addresses)
echo   - Nama SW (device names/hostnames)  
echo   - SN (serial numbers)
echo   - Model SW (device models)
echo.
echo   Supported Devices:
echo   - Arista EOS (via eAPI/JSON-RPC)
echo   - More vendors coming soon...
echo.
echo   Files and Directories:
echo   - Configuration: backend\commands.yaml
echo   - Output Files: output\
echo   - Uploaded Files: uploads\
echo   - Log Files: output\network_fetcher_*.log
echo.
echo   For detailed help, see README.md
echo   For troubleshooting, check the log files in output\
echo.
echo   Opening browser automatically...
echo ================================================================
echo.

REM Open the frontend URL in default browser
echo Opening http://localhost:3000 in your default browser...
start http://localhost:3000

REM Show process status
echo.
echo Development servers are now running in separate windows.
echo You can monitor their output in the opened command windows.
echo.
echo To stop the servers:
echo - Close the Backend window or press Ctrl+C
echo - Close the Frontend window or press Ctrl+C
echo.
echo This information window will close automatically in 10 seconds...
timeout /t 10 /nobreak >nul