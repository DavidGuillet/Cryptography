@echo off
REM Run Passveurd Streamlit app
REM Run from project root or scripts folder

set SCRIPT_DIR=%~dp0
cd /d "%SCRIPT_DIR%.."

echo Activating cryptography-scripts environment...
call conda activate cryptography-scripts

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo Could not activate environment. Create it first with: scripts\create_env.bat
    exit /b 1
)

echo Starting Streamlit app...
streamlit run App/app.py
