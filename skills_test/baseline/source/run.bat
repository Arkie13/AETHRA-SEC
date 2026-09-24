@echo off
rem ===========================================================================
rem  AETHRA-SEC launcher (Windows)
rem
rem   run.bat                 start the desktop console
rem   run.bat --check         run diagnostics and exit
rem   run.bat --headless      run the services without the interface
rem   run.bat --no-migrate    start without touching the database schema
rem
rem  Any argument is passed straight through to "python -m aethra_sec.main".
rem  Run setup.bat first if you have not installed the dependencies yet.
rem
rem  Live packet capture needs the Npcap driver and, on most installations, an
rem  elevated process: right-click this file and choose "Run as administrator"
rem  if the interface list on the Network Monitoring screen comes up empty.
rem ===========================================================================

setlocal
pushd "%~dp0"

set "PYTHON=.venv\Scripts\python.exe"

if not exist "%PYTHON%" (
    echo.
    echo   The virtual environment is missing ^(.venv^).
    echo   Run setup.bat once to create it and install the dependencies.
    echo.
    popd
    pause
    exit /b 2
)

if not exist ".env" (
    echo.
    echo   WARNING: no .env file found, so the built-in defaults will be used
    echo   ^(database aethra_app@127.0.0.1:3306/aethra_sec, no password^).
    echo   Copy .env.example to .env and set your database password and your
    echo   authorised networks before assessing anything.
    echo.
)

"%PYTHON%" -m aethra_sec.main %*
set "EXITCODE=%ERRORLEVEL%"

if not "%EXITCODE%"=="0" (
    echo.
    echo   AETHRA-SEC exited with code %EXITCODE%.
    echo   Run "run.bat --check" for the diagnostics, or read logs\aethra_sec.log.
    echo.
    pause
)

popd
endlocal & exit /b %EXITCODE%
