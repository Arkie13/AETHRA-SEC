<#
.SYNOPSIS
    Create the AETHRA-SEC desktop shortcut.

.DESCRIPTION
    Places "AETHRA-SEC.lnk" on the current user's desktop, pointing at the
    run.bat next to this script's parent folder.

    Nothing is hard-coded. Every path is derived from where this script sits,
    so the whole AETHRA-SEC folder can be moved to another drive and re-running
    this rebuilds a working shortcut. Re-running is always safe: an existing
    shortcut is overwritten in place, never duplicated.

    The console starts minimised rather than hidden. Hiding it entirely would
    need a wrapper that also swallows run.bat's error output and its pause on
    a non-zero exit, which is exactly what an operator needs to see when
    something fails to start.

.PARAMETER Force
    Replace an existing shortcut without asking.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File launcher\create_shortcut.ps1
#>

[CmdletBinding()]
param(
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

# --- resolve everything from this script's own location --------------------
$launcherDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$appRoot     = (Resolve-Path (Join-Path $launcherDir '..')).Path
$runBat      = Join-Path $appRoot 'run.bat'
$iconPath    = Join-Path $appRoot 'assets\aethra-sec.ico'

Write-Host ''
Write-Host '  AETHRA-SEC desktop shortcut'
Write-Host ('  Application folder: {0}' -f $appRoot)

if (-not (Test-Path -LiteralPath $runBat)) {
    Write-Host ''
    Write-Host '  [FAIL] run.bat was not found next to this script.' -ForegroundColor Red
    Write-Host '         Run this from inside the AETHRA-SEC folder.'
    exit 2
}

# --- the icon, generated from the application's own logo -------------------
if (-not (Test-Path -LiteralPath $iconPath)) {
    Write-Host '  [ .. ] Icon missing; generating it'
    $python = Join-Path $appRoot '.venv\Scripts\python.exe'
    if (-not (Test-Path -LiteralPath $python)) { $python = 'python' }
    & $python (Join-Path $launcherDir 'make_icon.py')
    if ($LASTEXITCODE -ne 0) {
        Write-Host '  [WARN] Could not generate the icon; using the default.' -ForegroundColor Yellow
    }
}

# --- the desktop, wherever it actually is ----------------------------------
# GetFolderPath, not "$env:USERPROFILE\Desktop": a desktop redirected into
# OneDrive lives somewhere else entirely, and writing to the literal path
# would silently create a shortcut nobody sees.
$desktop = [Environment]::GetFolderPath('Desktop')
if ([string]::IsNullOrWhiteSpace($desktop) -or -not (Test-Path -LiteralPath $desktop)) {
    Write-Host '  [FAIL] Could not locate your Desktop folder.' -ForegroundColor Red
    exit 3
}
$shortcutPath = Join-Path $desktop 'AETHRA-SEC.lnk'

if ((Test-Path -LiteralPath $shortcutPath) -and -not $Force) {
    Write-Host '  [ .. ] Replacing the existing shortcut'
}

# --- write it --------------------------------------------------------------
try {
    $shell    = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($shortcutPath)

    # cmd.exe /c rather than run.bat directly: the console then closes when
    # AETHRA-SEC exits cleanly, while run.bat's own pause still holds it open
    # on a failure so the error stays readable.
    $shortcut.TargetPath       = "$env:ComSpec"
    $shortcut.Arguments        = ('/c ""{0}""' -f $runBat)
    $shortcut.WorkingDirectory = $appRoot
    $shortcut.WindowStyle      = 7          # minimised
    $shortcut.Description      = 'AETHRA-SEC Security Operations Console'
    if (Test-Path -LiteralPath $iconPath) {
        $shortcut.IconLocation = "$iconPath,0"
    }
    $shortcut.Save()
}
catch {
    Write-Host ''
    Write-Host ('  [FAIL] Could not create the shortcut: {0}' -f $_.Exception.Message) -ForegroundColor Red
    exit 4
}
finally {
    if ($shell) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($shell) }
}

if (-not (Test-Path -LiteralPath $shortcutPath)) {
    Write-Host '  [FAIL] The shortcut was not written.' -ForegroundColor Red
    exit 5
}

Write-Host ('  [ OK ] {0}' -f $shortcutPath) -ForegroundColor Green
Write-Host '         Double-click AETHRA-SEC on your desktop to start the console.'
Write-Host ''
exit 0
