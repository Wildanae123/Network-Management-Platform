@REM INSTALL.bat
@echo off
title Network Management Platform - Environment Setup

REM Check for debug mode
if "%1"=="--debug" (
    echo DEBUG MODE ENABLED
    set DEBUG_MODE=1
) else (
    set DEBUG_MODE=0
)

echo ================================================================
echo.
echo   Network Management Platform v2.2.0
echo   Setting up Development Environment...
echo.
echo ================================================================

REM Check if we're in the right directory
if not exist "frontend" (
    echo ERROR: frontend folder not found!
    echo Please run this script from the project root directory.
    pause
    exit /b 1
)

if not exist "backend" (
    echo ERROR: backend folder not found!
    echo Please run this script from the project root directory.
    pause
    exit /b 1
)

REM Check if required tools are installed
echo Checking system requirements...

REM Check Node.js
echo Checking Node.js...
node --version >nul 2>&1
if not %errorlevel%==0 (
    echo ERROR: Node.js is not installed or not in PATH!
    echo Please install Node.js from https://nodejs.org/
    echo Make sure to restart your command prompt after installation.
    pause
    exit /b 1
)
echo ✓ Node.js is available

REM Check npm
echo Checking npm...
call npm --version >nul 2>&1
if not %errorlevel%==0 (
    echo ERROR: npm is not installed or not in PATH!
    echo npm should come with Node.js installation.
    echo Make sure to restart your command prompt after Node.js installation.
    pause
    exit /b 1
)
echo ✓ npm is available

REM Check Python
echo Checking Python...
python --version >nul 2>&1
if not %errorlevel%==0 (
    echo ERROR: Python is not installed or not in PATH!
    echo Please install Python from https://python.org/
    echo Make sure to check "Add Python to PATH" during installation.
    pause
    exit /b 1
)
echo ✓ Python is available

REM Check pip
echo Checking pip...
pip --version >nul 2>&1
if not %errorlevel%==0 (
    echo ERROR: pip is not installed or not in PATH!
    echo pip should come with Python installation.
    echo Try running: python -m ensurepip --upgrade
    pause
    exit /b 1
)
echo ✓ pip is available

echo All system requirements met!
echo.

echo ================================================================
echo Step 1: Setting up Frontend Environment
echo ================================================================
echo.

cd frontend
if errorlevel 1 (
    echo ERROR: Failed to change to frontend directory!
    pause
    exit /b 1
)

REM Check if package.json exists
if not exist "package.json" (
    echo ERROR: package.json not found in frontend directory!
    echo Please ensure the frontend project is properly set up.
    cd ..
    pause
    exit /b 1
) else (
    echo ✓ package.json found
)

REM Check if node_modules exists
if not exist "node_modules" (
    echo Installing frontend dependencies...
    echo This may take several minutes...
    call npm install
    if %errorlevel% neq 0 (
        echo ERROR: Frontend dependency installation failed!
        echo Error code: %errorlevel%
        cd ..
        pause
        exit /b 1
    )
    echo ✓ Frontend dependencies installed successfully!
) else (
    echo ✓ Frontend dependencies already installed.
)

REM Verify key dependencies
echo Checking for required frontend dependencies...
if exist "node_modules\react" (
    echo ✓ React found
) else (
    echo WARNING: React not found in node_modules
)

if exist "node_modules\vite" (
    echo ✓ Vite found
) else (
    echo WARNING: Vite not found in node_modules
)

if exist "node_modules\lucide-react" (
    echo ✓ Lucide React found
) else (
    echo WARNING: Lucide React not found in node_modules
)

if exist "node_modules\react-plotly.js" (
    echo ✓ React Plotly found
) else (
    echo WARNING: React Plotly not found in node_modules
)

echo Returning to root directory...
cd ..
if errorlevel 1 (
    echo ERROR: Failed to return to root directory!
    pause
    exit /b 1
)

echo ✓ Step 1 completed successfully!
echo.

echo ================================================================
echo Step 2: Setting up Backend Environment
echo ================================================================
echo.

cd backend
if errorlevel 1 (
    echo ERROR: Failed to change to backend directory!
    pause
    exit /b 1
)

REM Check if server.py exists
if not exist "server.py" (
    echo ERROR: server.py not found in backend directory!
    echo Please ensure the backend server file is properly set up.
    cd ..
    pause
    exit /b 1
) else (
    echo ✓ server.py found
)

REM Check if requirements.txt exists
if not exist "requirements.txt" (
    echo ERROR: requirements.txt not found in backend directory!
    echo Please ensure the requirements file is properly set up.
    cd ..
    pause
    exit /b 1
) else (
    echo ✓ requirements.txt found
)

REM Check if virtual environment exists
if not exist "venv" (
    echo Creating Python virtual environment...
    python -m venv venv
    if not %errorlevel%==0 (
        echo ERROR: Failed to create virtual environment!
        echo Make sure Python is installed and available in PATH.
        cd ..
        pause
        exit /b 1
    )
    echo ✓ Virtual environment created successfully!
) else (
    echo ✓ Virtual environment already exists.
)

REM Verify virtual environment was created properly
if not exist "venv\Scripts\pip.exe" (
    echo ERROR: Virtual environment was not created properly!
    echo pip.exe not found in venv\Scripts\
    echo Trying to recreate virtual environment...
    rmdir /s /q venv 2>nul
    python -m venv venv
    if not %errorlevel%==0 (
        echo ERROR: Still failed to create virtual environment!
        echo Please check if Python is properly installed.
        cd ..
        pause
        exit /b 1
    )
)

REM Activate virtual environment and install dependencies
echo Activating virtual environment...
call venv\Scripts\activate.bat
if not %errorlevel%==0 (
    echo ERROR: Failed to activate virtual environment!
    cd ..
    pause
    exit /b 1
)

echo Installing backend dependencies...

REM First upgrade pip to latest version
echo Upgrading pip to latest version...
python -m pip install --upgrade pip
if not %errorlevel%==0 (
    echo WARNING: Failed to upgrade pip, continuing with current version...
)

REM Install wheel and setuptools first
echo Installing build tools...
pip install wheel setuptools
if not %errorlevel%==0 (
    echo WARNING: Failed to install build tools, continuing...
)

if exist "requirements.txt" (
    echo Installing from requirements.txt...
    echo This may take several minutes...
    echo Trying with --only-binary option first...
    pip install --only-binary=all -r requirements.txt
    if not %errorlevel%==0 (
        echo Binary installation failed, trying with --no-build-isolation...
        pip install --no-build-isolation -r requirements.txt
        if not %errorlevel%==0 (
            echo Alternative installation failed, trying standard installation...
            pip install -r requirements.txt
            if not %errorlevel%==0 (
                echo ERROR: Backend dependency installation from requirements.txt failed!
                echo Error code: %errorlevel%
                echo.
                echo Trying fallback installation with compatible versions...
                goto fallback_install
            )
        )
    )
) else (
    :fallback_install
    echo Installing individual packages with compatible versions...
    echo This may take several minutes...
    pip install flask==3.0.0 flask-cors==4.0.0 requests==2.31.0 plotly==5.17.0 pyyaml==6.0.1 jsonrpclib-pelix==0.4.3.2 openpyxl==3.1.2 werkzeug==3.0.0 urllib3==2.0.7
    if not %errorlevel%==0 (
        echo Trying to install pandas separately...
        pip install pandas
        if not %errorlevel%==0 (
            echo ERROR: Critical dependency installation failed!
            echo Error code: %errorlevel%
            echo.
            echo Please try running: pip install --only-binary=all pandas
            cd ..
            pause
            exit /b 1
        )
    )
)

echo Backend dependencies installed successfully!

echo Deactivating virtual environment...
deactivate

echo Returning to root directory...
cd ..
if errorlevel 1 (
    echo ERROR: Failed to return to root directory!
    pause
    exit /b 1
)

echo Step 2 completed successfully!
echo.
echo ================================================
echo  Setup Complete!
echo.
echo  To start the development environment, run:
echo  START-HERE.bat
echo ================================================
echo.
pause