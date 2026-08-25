@echo off
rem ===========================================================================
rem  AETHRA-SEC first-run setup (Windows)
rem
rem  Creates the virtual environment, installs the dependencies, prepares .env,
rem  creates the database schema and offers to create the first administrator.
rem  Safe to run again: every step checks what is already done.
rem
rem  Prerequisites, installed separately:
rem    * Python 3.10+ with the "tcl/tk and IDLE" option
rem    * MySQL 8.0+ or MariaDB 10.6+, running
rem    * Nmap and Wireshark/TShark for assessment and capture
rem ===========================================================================

setlocal
pushd "%~dp0"

echo.
echo  ===========================================================
echo   AETHRA-SEC setup
echo  ===========================================================
echo.

rem --- 1. Python ------------------------------------------------------------
python --version >nul 2>&1
if errorlevel 1 (
    echo   [FAIL] Python was not found on PATH.
    echo          Install Python 3.10+ and tick "Add python.exe to PATH".
    goto :failed
)
for /f "tokens=*" %%v in ('python --version 2^>^&1') do echo   [ OK ] %%v

python -c "import tkinter" >nul 2>&1
if errorlevel 1 (
    echo   [FAIL] This Python has no tkinter, so the console cannot open.
    echo          Re-run the Python installer, choose Modify, and enable
    echo          "tcl/tk and IDLE".
    goto :failed
)
echo   [ OK ] tkinter is available

rem --- 2. Virtual environment ----------------------------------------------
if exist ".venv\Scripts\python.exe" (
    echo   [ OK ] Virtual environment already exists
) else (
    echo   [ .. ] Creating the virtual environment
    python -m venv .venv
    if errorlevel 1 (
        echo   [FAIL] Could not create .venv
        goto :failed
    )
    echo   [ OK ] Virtual environment created
)

set "PYTHON=.venv\Scripts\python.exe"

rem --- 3. Dependencies ------------------------------------------------------
echo   [ .. ] Installing dependencies from requirements.txt
"%PYTHON%" -m pip install --upgrade pip >nul
"%PYTHON%" -m pip install -r requirements.txt
if errorlevel 1 (
    echo   [FAIL] Dependency installation failed. See the output above.
    goto :failed
)
echo   [ OK ] Dependencies installed

rem --- 4. Configuration -----------------------------------------------------
if exist ".env" (
    echo   [ OK ] .env already exists ^(left untouched^)
) else (
    copy /y ".env.example" ".env" >nul
    echo   [ OK ] .env created from .env.example
    echo.
    echo   Set at least these two before continuing:
    echo       AETHRA_DB_PASSWORD          the password of your MySQL account
    echo       AETHRA_AUTHORIZED_NETWORKS  the networks you may scan/monitor
    echo.
    echo   Opening .env in Notepad - save and close it to continue.
    notepad ".env"
)

rem --- 5. Database ----------------------------------------------------------
echo.
echo   [ .. ] Creating the database schema
"%PYTHON%" scripts\init_db.py
if errorlevel 1 (
    echo.
    echo   [FAIL] The schema could not be created.
    echo          Check that MySQL is running and that the credentials in .env
    echo          are correct, then run setup.bat again. If the account may not
    echo          create databases, apply sql\aethra_sec_schema.sql as root:
    echo              mysql -u root -p ^< sql\aethra_sec_schema.sql
    goto :failed
)
echo   [ OK ] Schema ready

rem --- 6. First administrator ----------------------------------------------
echo.
echo   Create the first administrator account now? The password is prompted
echo   for and never echoed. Skip this if you already have an account.
choice /c YN /n /m "   Create an account? [Y/N] "
if errorlevel 2 goto :health
"%PYTHON%" scripts\create_admin.py

rem --- 7. Diagnostics -------------------------------------------------------
:health
echo.
echo   [ .. ] Running diagnostics
"%PYTHON%" scripts\health_check.py

echo.
echo  ===========================================================
echo   Setup finished. Start AETHRA-SEC with:  run.bat
echo  ===========================================================
echo.
popd
pause
exit /b 0

:failed
echo.
echo   Setup did not complete. Fix the problem above and run setup.bat again.
echo.
popd
pause
exit /b 1
