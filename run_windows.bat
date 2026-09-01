@echo off
setlocal EnableExtensions

rem Start the AI hacking tool from this batch file's directory.
set "ROOT=%~dp0"
cd /d "%ROOT%"

echo.
echo ==============================================
echo   AI Hacking Tool - Windows Local Launcher
echo ==============================================
echo.

if not exist ".venv\Scripts\python.exe" (
    echo [INFO] Creating Python virtual environment...
    py -3.12 -m venv .venv
    if errorlevel 1 (
        echo [ERROR] Could not create .venv. Install Python 3.12+ and try again.
        exit /b 1
    )
)

if not exist ".venv\Scripts\uvicorn.exe" (
    echo [INFO] Installing backend dependencies...
    ".venv\Scripts\python.exe" -m pip install --upgrade pip
    ".venv\Scripts\python.exe" -m pip install -e .
    if errorlevel 1 (
        echo [ERROR] Backend dependency installation failed.
        exit /b 1
    )
)

if not exist "frontend\node_modules" (
    echo [INFO] Installing frontend dependencies...
    npm --prefix frontend install
    if errorlevel 1 (
        echo [ERROR] Frontend dependency installation failed. Install Node.js 18+.
        exit /b 1
    )
)

if defined SHODAN_API_KEY (
    echo [INFO] Shodan configuration: environment variable detected.
) else (
    echo [INFO] Shodan configuration: using local YAML fallback if configured.
    echo [INFO] No API key is embedded in this launcher.
)

echo [INFO] Starting FastAPI backend at http://127.0.0.1:8000
start "AI Hacking Tool Backend" /D "%ROOT%" "%ComSpec%" /k ".venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload"

echo [INFO] Starting React frontend at http://localhost:5173
start "AI Hacking Tool Frontend" /D "%ROOT%frontend" "%ComSpec%" /k "npm run dev"

echo.
echo [READY] Open http://localhost:5173 in your browser.
echo [INFO] Close the two command windows to stop the application.
echo.
endlocal
