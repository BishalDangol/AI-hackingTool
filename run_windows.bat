@echo off
setlocal EnableExtensions

rem Always run relative to this file, not the current terminal directory.
set "ROOT=%~dp0"
cd /d "%ROOT%"

echo.
echo ==============================================
echo   AI Hacking Tool - FYP Demo Launcher
echo ==============================================
echo.

if not exist ".venv\Scripts\python.exe" (
    echo [INFO] Creating Python virtual environment...
    py -3 -m venv .venv
    if errorlevel 1 (
        echo [ERROR] Python was not found or the virtual environment could not be created.
        pause
        exit /b 1
    )
)

if not exist ".venv\Scripts\uvicorn.exe" (
    echo [INFO] Installing backend dependencies...
    ".venv\Scripts\python.exe" -m pip install --upgrade pip
    ".venv\Scripts\python.exe" -m pip install -e .
    if errorlevel 1 (
        echo [ERROR] Backend dependency installation failed.
        pause
        exit /b 1
    )
)

if not exist "frontend\node_modules" (
    echo [INFO] Installing frontend dependencies...
    npm --prefix frontend install
    if errorlevel 1 (
        echo [ERROR] Frontend dependency installation failed. Install Node.js 18 or newer.
        pause
        exit /b 1
    )
)

rem Automatically enable the deterministic synthetic lab when it is beside this repo.
set "LAB_REPLAY=%ROOT%..\SandboxVernuableEnv\mock_theharvester.py"
if exist "%LAB_REPLAY%" (
    set "THEHARVESTER_COMMAND=%LAB_REPLAY%"
    echo [INFO] Synthetic replay enabled:
    echo        %LAB_REPLAY%
) else (
    echo [INFO] Synthetic replay not found beside the application.
    echo [INFO] Live theHarvester mode will be used.
    echo [INFO] For the FYP demo, place both folders under E:\sarvers\:
    echo        E:\sarvers\AI-hackingTool
    echo        E:\sarvers\SandboxVernuableEnv
)

if defined SHODAN_API_KEY (
    echo [INFO] Shodan key: environment variable detected.
) else (
    echo [INFO] Shodan key: local YAML fallback will be used if configured.
)

echo.
echo [INFO] Starting backend at http://127.0.0.1:8000
start "AI Hacking Tool Backend" /D "%ROOT%" "%ComSpec%" /k ".venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload"

echo [INFO] Starting frontend at http://localhost:5173
start "AI Hacking Tool Frontend" /D "%ROOT%frontend" "%ComSpec%" /k "npm run dev"
echo.
echo [READY] Open http://localhost:5173
echo [READY] In Domain OSINT, scan target: lab.test
echo [READY] Expected emails: security@lab.test, research@lab.test
echo [READY] Close the backend and frontend windows to stop the demo.
echo.
pause
endlocal
