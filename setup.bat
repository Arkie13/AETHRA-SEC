@echo off
rem ===========================================================================
rem  AETHRA-SEC development setup (Windows)
rem
rem  For working from the source checkout. If you installed AETHRA-SEC with
rem  AETHRA-SEC-Setup.exe you do not need this file at all - the installed
rem  application runs its own setup wizard the first time it starts.
rem
rem  This script prepares the Python environment and then hands over to
rem  aethra_sec.setup.console, which is the SAME setup the graphical wizard
rem  runs: the same dependency probes, the same configuration writer, the same
rem  database provisioning, the same administrator creation and the same health
rem  report. There is deliberately no second implementation here - two setup
rem  paths that each knew how to create an administrator would eventually
rem  create two different ones.
rem
rem  Safe to run again. Every step checks what is already done, an existing
rem  configuration is offered back as the default, and an existing
rem  administrator is reported rather than replaced.
rem
rem  Prerequisites, installed separately:
rem    * Python 3.10+ with the "tcl/tk and IDLE" option
rem    * MySQL 8.0+ / MariaDB 10.6+ / XAMPP, running
rem    * Nmap, Wireshark/TShark (with Npcap) for assessment and capture
rem    * Snort, optionally, for intrusion detection
rem ===========================================================================

setlocal
pushd "%~dp0"

echo.
echo  ===========================================================
echo   AETHRA-SEC development setup
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

rem --- 4. Application icon --------------------------------------------------
if exist "assets\aethra-sec.ico" (
    echo   [ OK ] Application icon present
) else (
    echo   [ .. ] Rendering the application icon
    "%PYTHON%" launcher\make_icon.py
)

rem --- 5. Setup -------------------------------------------------------------
rem  Everything from here is the shared setup: administrator, database,
rem  security tools, network interface, email and the health check.
rem
rem  Choose the graphical wizard or the console. Both do exactly the same
rem  thing; the wizard is easier to read, the console works over SSH.
echo.
echo   ===========================================================
echo    Setup: administrator, database, tools, interface, email
echo   ===========================================================
echo.
echo     [1] Graphical setup wizard  ^(recommended^)
echo     [2] Console setup
echo     [3] Skip setup - only run the health check
echo.
choice /c 123 /n /m "   Choose [1/2/3]: "
if errorlevel 3 goto :healthonly
if errorlevel 2 goto :consolesetup

:wizard
echo.
echo   [ .. ] Starting the graphical setup wizard
"%PYTHON%" -m aethra_sec.main --setup
if errorlevel 1 (
    echo   [WARN] The wizard did not complete. Run setup.bat again, or choose
    echo          the console setup.
)
goto :shortcut

:consolesetup
echo.
"%PYTHON%" -m aethra_sec.setup.console
if errorlevel 1 (
    echo.
    echo   [FAIL] Setup did not complete. Fix the problem reported above and
    echo          run setup.bat again.
    goto :failed
)
goto :shortcut

:healthonly
echo.
"%PYTHON%" -m aethra_sec.setup.console --check-only
goto :shortcut

rem --- 6. Desktop shortcut --------------------------------------------------
:shortcut
echo.
echo   [ .. ] Creating the desktop shortcut
powershell -NoProfile -ExecutionPolicy Bypass -File "launcher\create_shortcut.ps1"
if errorlevel 1 (
    echo   [WARN] The desktop shortcut could not be created.
    echo          run.bat still starts AETHRA-SEC normally.
)

echo.
echo  ===========================================================
echo   Setup finished.
echo     Desktop:  double-click the AETHRA-SEC icon
echo     Terminal: run.bat
echo     Health:   run.bat --check
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
