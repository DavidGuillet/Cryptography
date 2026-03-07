@echo off
REM Create Python environment for Cryptography project
REM Run from project root or scripts folder

set SCRIPT_DIR=%~dp0
cd /d "%SCRIPT_DIR%.."

echo Creating conda environment from scripts/requirements.yaml...
conda env create -f scripts/requirements.yaml

if %ERRORLEVEL% EQU 0 (
    echo.
    echo Environment 'cryptography-scripts' created successfully.
    echo Activate with: conda activate cryptography-scripts
) else (
    echo.
    echo Environment creation failed. If env already exists, use: conda env update -f scripts/requirements.yaml
    exit /b 1
)
