@echo off
REM Create Python environment for Cryptography project (locally in .\env)
REM Requires PYTHON_PATH environment variable set to your conda install (e.g. C:\ProgramData\anaconda3)
REM Run from project root or scripts folder

set SCRIPT_DIR=%~dp0
cd /d "%SCRIPT_DIR%.."
set PROJECT_ROOT=%CD%

if not defined PYTHON_PATH (
    echo ERROR: PYTHON_PATH is not set. Set it to your conda install folder, e.g.:
    echo   set PYTHON_PATH=C:\ProgramData\anaconda3
    echo Or add it in System/User Environment Variables.
    exit /b 1
)

set CONDA_BAT=%PYTHON_PATH%\Scripts\activate.bat
if not exist "%CONDA_BAT%" (
    echo ERROR: conda not found at %PYTHON_PATH%\Scripts\activate.bat
    exit /b 1
)

echo Initializing conda from %PYTHON_PATH%...
call "%CONDA_BAT%" "%PYTHON_PATH%"

echo Creating environment at %PROJECT_ROOT%\env...
conda env create -f scripts/requirements.yaml --prefix "%PROJECT_ROOT%\env"
set CREATE_OK=%ERRORLEVEL%

if %CREATE_OK% NEQ 0 (
    echo.
    echo Environment may already exist. Attempting kernel registration...
    if not exist "%PROJECT_ROOT%\env\python.exe" (
        echo ERROR: No env at %PROJECT_ROOT%\env. To update existing env, run:
        echo   conda env update -f scripts/requirements.yaml --prefix "%PROJECT_ROOT%\env"
        exit /b 1
    )
)

echo.
echo Registering Jupyter kernel "Python (Cryptography)"...
"%PROJECT_ROOT%\env\python.exe" -m ipykernel install --user --name cryptography-scripts --display-name "Python (Cryptography)"

if %ERRORLEVEL% EQU 0 (
    echo.
    if %CREATE_OK% EQU 0 (
        echo Environment created at %PROJECT_ROOT%\env
    )
    echo Jupyter kernel registered. Activate with: conda activate "%PROJECT_ROOT%\env"
) else (
    echo.
    echo WARNING: Jupyter kernel registration failed. Ensure ipykernel is installed in the env.
    if %CREATE_OK% NEQ 0 exit /b 1
)
