@echo off
REM Run tests for Cryptography project
REM Requires PYTHON_PATH environment variable (see create_env.bat)
REM Run from project root or scripts folder

set SCRIPT_DIR=%~dp0
cd /d "%SCRIPT_DIR%.."
set PROJECT_ROOT=%CD%
set ENV_PATH=%PROJECT_ROOT%\env

if not defined PYTHON_PATH (
    echo ERROR: PYTHON_PATH is not set. Set it to your conda install folder.
    exit /b 1
)

if not exist "%ENV_PATH%\python.exe" (
    echo ERROR: Environment not found at %ENV_PATH%
    echo Run scripts\create_env.bat first.
    exit /b 1
)

echo Activating environment...
call "%PYTHON_PATH%\Scripts\activate.bat" "%PYTHON_PATH%"
call conda activate "%ENV_PATH%"

if %ERRORLEVEL% NEQ 0 (
    echo Could not activate environment.
    exit /b 1
)

echo Running tests...
pytest tests/ -v
