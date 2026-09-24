<#
.SYNOPSIS
    Build AETHRA-SEC.exe and AETHRA-SEC-Setup.exe.

.DESCRIPTION
    Two stages, in order:

      1. PyInstaller freezes the application into build\dist\AETHRA-SEC\,
         producing AETHRA-SEC.exe (windowed) and aethra-sec-cli.exe (console)
         beside the Python runtime and the packaged assets.
      2. Inno Setup compiles that directory into build\installer\
         AETHRA-SEC-Setup.exe.

    The version comes from aethra_sec/version.py and is passed to both stages,
    so the number in Explorer's Properties, the number in Add/Remove Programs
    and the number the application reports cannot disagree.

    Everything is resolved from this script's own location, so the repository
    can be moved or cloned anywhere.

.PARAMETER SkipTests
    Do not run the test suite first. The default is to run it: shipping an
    installer built from code that does not pass its own tests is the failure
    this flag exists to make deliberate.

.PARAMETER SkipInstaller
    Build the executables but do not compile the installer. Useful when Inno
    Setup is not installed on the build machine.

.PARAMETER Clean
    Delete previous build output first.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File packaging\build.ps1
#>

[CmdletBinding()]
param(
    [switch]$SkipTests,
    [switch]$SkipInstaller,
    [switch]$Clean
)

$ErrorActionPreference = 'Stop'

$PackagingDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot  = (Resolve-Path (Join-Path $PackagingDir '..')).Path
$BuildDir     = Join-Path $ProjectRoot 'build'
$DistDir      = Join-Path $BuildDir 'dist'
$WorkDir      = Join-Path $BuildDir 'work'
$InstallerDir = Join-Path $BuildDir 'installer'
$AppDir       = Join-Path $DistDir 'AETHRA-SEC'

function Write-Stage([string]$Text) {
    Write-Host ''
    Write-Host ('=' * 70) -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host ('=' * 70) -ForegroundColor Cyan
}

function Fail([string]$Text) {
    Write-Host ''
    Write-Host "  [FAIL] $Text" -ForegroundColor Red
    exit 1
}

# --- the interpreter to build with ----------------------------------------
# The virtual environment, when there is one: it holds the exact dependency
# versions that go into the build, and building against a different set is how
# a build ends up shipping something that was never tested.
$Python = Join-Path $ProjectRoot '.venv\Scripts\python.exe'
if (-not (Test-Path $Python)) {
    $Python = (Get-Command python -ErrorAction SilentlyContinue).Source
    if (-not $Python) { Fail 'No Python found. Create .venv or install Python 3.10+.' }
    Write-Host "  [WARN] .venv not found; building with $Python" -ForegroundColor Yellow
}

Write-Stage 'AETHRA-SEC build'
Write-Host "  Project    : $ProjectRoot"
Write-Host "  Interpreter: $Python"

# --- version --------------------------------------------------------------
$Version = & $Python -c "import sys; sys.path.insert(0, r'$ProjectRoot'); from aethra_sec.version import APP_VERSION; print(APP_VERSION)"
if ($LASTEXITCODE -ne 0 -or -not $Version) { Fail 'Could not read APP_VERSION from aethra_sec/version.py.' }
$Version = $Version.Trim()
Write-Host "  Version    : $Version"

# --- dependencies ---------------------------------------------------------
& $Python -c "import PyInstaller" 2>$null
if ($LASTEXITCODE -ne 0) {
    Fail 'PyInstaller is not installed. Run:  .venv\Scripts\python.exe -m pip install pyinstaller'
}

# --- tests ----------------------------------------------------------------
if ($SkipTests) {
    Write-Host '  [SKIP] Tests skipped by request.' -ForegroundColor Yellow
} else {
    Write-Stage 'Stage 0 of 2 - test suite'
    Push-Location $ProjectRoot
    try {
        & $Python -m pytest tests/ -q
        if ($LASTEXITCODE -ne 0) { Fail 'The test suite failed. Fix it before building an installer.' }
    } finally {
        Pop-Location
    }
    Write-Host '  [ OK ] Tests passed.' -ForegroundColor Green
}

# --- clean ----------------------------------------------------------------
if ($Clean -and (Test-Path $BuildDir)) {
    Write-Host "  [ .. ] Removing $BuildDir"
    Remove-Item $BuildDir -Recurse -Force
}

# --- stage 1: PyInstaller -------------------------------------------------
Write-Stage 'Stage 1 of 2 - freezing the application (PyInstaller)'
Push-Location $ProjectRoot
try {
    & $Python -m PyInstaller (Join-Path $PackagingDir 'AETHRA-SEC.spec') `
        --noconfirm --distpath $DistDir --workpath $WorkDir
    if ($LASTEXITCODE -ne 0) { Fail 'PyInstaller failed.' }
} finally {
    Pop-Location
}

$GuiExe = Join-Path $AppDir 'AETHRA-SEC.exe'
$CliExe = Join-Path $AppDir 'aethra-sec-cli.exe'
if (-not (Test-Path $GuiExe)) { Fail "PyInstaller did not produce $GuiExe" }
if (-not (Test-Path $CliExe)) { Fail "PyInstaller did not produce $CliExe" }

$SizeMB = (Get-ChildItem $AppDir -Recurse -File | Measure-Object Length -Sum).Sum / 1MB
Write-Host ('  [ OK ] {0}  ({1:N1} MB total)' -f $GuiExe, $SizeMB) -ForegroundColor Green

# Prove the frozen build runs before wrapping it in an installer. A build that
# cannot report its own version is not one to ship, and finding that out here
# costs seconds where finding it out after installation costs a support call.
Write-Host '  [ .. ] Verifying the frozen executable'
$Reported = & $CliExe --version 2>&1
if ($LASTEXITCODE -ne 0) { Fail "The frozen executable did not run: $Reported" }
Write-Host "  [ OK ] $Reported" -ForegroundColor Green

# --- stage 2: Inno Setup --------------------------------------------------
if ($SkipInstaller) {
    Write-Host ''
    Write-Host '  [SKIP] Installer skipped by request.' -ForegroundColor Yellow
    Write-Host "  Application directory: $AppDir"
    exit 0
}

Write-Stage 'Stage 2 of 2 - compiling the installer (Inno Setup)'

$IsccCandidates = @(
    'C:\Program Files (x86)\Inno Setup 6\ISCC.exe',
    'C:\Program Files\Inno Setup 6\ISCC.exe',
    'C:\Program Files (x86)\Inno Setup 5\ISCC.exe'
)
$Iscc = $null
foreach ($candidate in $IsccCandidates) {
    if (Test-Path $candidate) { $Iscc = $candidate; break }
}
if (-not $Iscc) {
    $Iscc = (Get-Command ISCC.exe -ErrorAction SilentlyContinue).Source
}
if (-not $Iscc) {
    Fail @'
Inno Setup was not found.

Install it from https://jrsoftware.org/isdl.php (or: winget install JRSoftware.InnoSetup),
then run this script again. To build only the executables, pass -SkipInstaller.
'@
}
Write-Host "  Compiler   : $Iscc"

New-Item -ItemType Directory -Force $InstallerDir | Out-Null

& $Iscc `
    "/DAppVersion=$Version" `
    "/DSourceDir=$AppDir" `
    "/DOutputDir=$InstallerDir" `
    (Join-Path $PackagingDir 'aethra-sec.iss')
if ($LASTEXITCODE -ne 0) { Fail 'Inno Setup failed to compile the installer.' }

$Setup = Join-Path $InstallerDir 'AETHRA-SEC-Setup.exe'
if (-not (Test-Path $Setup)) { Fail "The installer was not produced at $Setup" }

$SetupMB = (Get-Item $Setup).Length / 1MB
$Hash = (Get-FileHash $Setup -Algorithm SHA256).Hash

Write-Stage 'Build complete'
Write-Host ('  Installer : {0}' -f $Setup) -ForegroundColor Green
Write-Host ('  Size      : {0:N1} MB' -f $SetupMB)
Write-Host ('  Version   : {0}' -f $Version)
Write-Host ('  SHA256    : {0}' -f $Hash)
Write-Host ''
Write-Host '  Install it, then double-click the AETHRA-SEC desktop icon.'
Write-Host '  The first launch runs the setup wizard.'
Write-Host ''
