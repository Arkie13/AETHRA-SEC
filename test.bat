@echo off
rem ===========================================================================
rem  AETHRA-SEC - OFFLINE SKILLS TEST
rem
rem  Double-click this file, or run:  test.bat
rem
rem  It checks the application against a known-good baseline, runs behavioural
rem  regression tests, and - when something is broken - names the file and the
rem  function and prints the original code for you to paste back.
rem
rem  IT NEVER EDITS YOUR SOURCE FILES. You make the repair by hand, then run
rem  this again.
rem
rem    test.bat                 full diagnostic run
rem    test.bat --no-modules    skip the per-module import scan (faster)
rem
rem  Works entirely offline. No internet, no cloud service.
rem ===========================================================================

setlocal
pushd "%~dp0"

rem --- Find a Python interpreter: the project venv first, then the PATH. -----
set "PYTHON="
if exist ".venv\Scripts\python.exe" set "PYTHON=.venv\Scripts\python.exe"
if not defined PYTHON (
    where python >nul 2>&1 && set "PYTHON=python"
)
if not defined PYTHON (
    where py >nul 2>&1 && set "PYTHON=py"
)
if not defined PYTHON (
    echo.
    echo ==========================================================================
    echo  PYTHON NOT FOUND
    echo ==========================================================================
    echo.
    echo  No Python interpreter was found.
    echo  Expected: .venv\Scripts\python.exe, or "python" on your PATH.
    echo.
    echo  Run setup.bat first.
    echo.
    popd
    endlocal
    exit /b 2
)

rem --- The baseline must exist before anything can be compared to it. -------
if not exist "skills_test\baseline\baseline_manifest.json" (
    echo.
    echo ==========================================================================
    echo  NO BASELINE RECORDED
    echo ==========================================================================
    echo.
    echo  The skills test compares the current code against a known-good copy,
    echo  and no copy has been recorded yet.
    echo.
    echo  Record one now ^(only from a WORKING system^):
    echo.
    echo     %PYTHON% skills_test\tools\make_baseline.py
    echo.
    popd
    endlocal
    exit /b 2
)

"%PYTHON%" skills_test\tools\runner.py %*
set "RESULT=%ERRORLEVEL%"

echo.
if "%RESULT%"=="0" (
    echo  Result: PASS
) else (
    echo  Result: FAIL - read the diagnosis above.
)
echo.

rem Pause only when double-clicked, so the window does not vanish.
echo %CMDCMDLINE% | find /i "/c" >nul
if not errorlevel 1 pause

popd
endlocal
exit /b %RESULT%
